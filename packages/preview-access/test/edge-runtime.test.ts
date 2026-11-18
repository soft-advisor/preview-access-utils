import assert from 'node:assert/strict';
import test from 'node:test';
import ts from 'typescript';
import { viewerRequestFunction } from '../src/edge.ts';

/*
 * CloudFront Functions (cloudfront-js-2.0) is ES 5.1 plus a few later features. Node runs the
 * other edge tests, and supports far more, so this test parses the generated code and rejects
 * syntax that the CloudFront runtime doesn't support. See
 * https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-javascript-runtime-20.html
 */
function unsupportedSyntax(code: string) {
  const source = ts.createSourceFile(
    'edge.js',
    code,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.JS,
  );
  const problems: string[] = [];
  const report = (node: ts.Node, problem: string) => {
    const { line } = source.getLineAndCharacterOfPosition(node.getStart());
    problems.push(`line ${line + 1}: ${problem}`);
  };
  const isAsync = (node: ts.Node) =>
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.AsyncKeyword);

  const visit = (node: ts.Node) => {
    if (ts.isForOfStatement(node)) report(node, 'for...of');
    if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node)) && isAsync(node)) {
      report(node, 'async closure');
    }
    if (ts.isClassLike(node)) report(node, 'class');
    if (ts.isObjectBindingPattern(node) || ts.isArrayBindingPattern(node))
      report(node, 'destructuring');
    if (ts.isParameter(node) && node.initializer) report(node, 'default parameter');
    if (ts.isSpreadElement(node) || ts.isSpreadAssignment(node)) report(node, 'spread');
    if (node.kind === ts.SyntaxKind.QuestionDotToken) report(node, 'optional chaining');
    if (node.kind === ts.SyntaxKind.QuestionQuestionToken) report(node, 'nullish coalescing');
    ts.forEachChild(node, visit);
  };
  visit(source);
  return {
    problems,
    syntaxErrors: (source as unknown as { parseDiagnostics: unknown[] }).parseDiagnostics,
  };
}

test('the generated edge function uses only syntax CloudFront Functions supports', () => {
  const { problems, syntaxErrors } = unsupportedSyntax(
    viewerRequestFunction({ domain: 'dev.example.com' }),
  );
  assert.deepEqual(syntaxErrors, []);
  assert.deepEqual(problems, []);
});

test('the compatibility check catches what broke 0.2.0', () => {
  const { problems } = unsupportedSyntax(
    'async function handler(event) { const r = await (async (s) => { for (const k of s) {} })([]); }',
  );
  assert.deepEqual(problems, ['line 1: async closure', 'line 1: for...of']);
});
