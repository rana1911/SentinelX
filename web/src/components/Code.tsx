// Lightweight Solidity highlighter — just enough to make the PoC readable.
// Dependency-free (no highlight.js) to keep the bundle tiny.
import type { ReactNode } from "react";

const KEYWORDS = new Set([
  "function", "contract", "interface", "library", "internal", "external",
  "public", "private", "pure", "view", "payable", "returns", "return",
  "memory", "storage", "calldata", "new", "require", "assert", "if", "else",
  "for", "while", "constructor", "emit", "this", "msg", "true", "false",
]);
const TYPES = new Set([
  "address", "bool", "mapping", "uint8", "uint256", "uint", "int", "bytes32",
  "bytes", "string",
]);

// splitter keeps delimiters: identifiers, strings, and everything else.
const TOKEN = /("(?:[^"\\]|\\.)*"|[A-Za-z_]\w*|.)/g;

function highlightLine(line: string, keyPrefix: string): ReactNode[] {
  const commentAt = line.indexOf("//");
  const code = commentAt >= 0 ? line.slice(0, commentAt) : line;
  const comment = commentAt >= 0 ? line.slice(commentAt) : "";

  const nodes: ReactNode[] = [];
  const matches = code.match(TOKEN) ?? [];
  matches.forEach((tok, i) => {
    const key = `${keyPrefix}-${i}`;
    if (tok.startsWith('"')) {
      nodes.push(<span className="st" key={key}>{tok}</span>);
    } else if (KEYWORDS.has(tok)) {
      nodes.push(<span className="kw" key={key}>{tok}</span>);
    } else if (TYPES.has(tok)) {
      nodes.push(<span className="ty" key={key}>{tok}</span>);
    } else {
      nodes.push(<span key={key}>{tok}</span>);
    }
  });
  if (comment) nodes.push(<span className="cm" key={`${keyPrefix}-cm`}>{comment}</span>);
  return nodes;
}

export function Code({ src }: { src: string }) {
  const lines = src.replace(/\n+$/, "").split("\n");
  return (
    <pre className="code">
      {lines.map((line, i) => (
        <span key={i}>
          {highlightLine(line, String(i))}
          {"\n"}
        </span>
      ))}
    </pre>
  );
}
