#!/usr/bin/env node

import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

const defaultInputs = ["README.md", "docs", "AGENTS.md"];
const cwd = process.cwd();
const jsonOutput = process.argv.includes("--json");
const requestedInputs = process.argv
  .slice(2)
  .filter((argument) => argument !== "--json");
const inputs = requestedInputs.length > 0 ? requestedInputs : defaultInputs;

function displayPath(filePath) {
  return path.relative(cwd, filePath).replaceAll("\\", "/") || ".";
}

function collectMarkdownFiles(inputPath, files, errors) {
  const absolutePath = path.resolve(cwd, inputPath);
  if (!existsSync(absolutePath)) {
    errors.push({
      file: inputPath.replaceAll("\\", "/"),
      line: 0,
      target: null,
      reason: "input does not exist",
    });
    return;
  }

  const stat = lstatSync(absolutePath);
  if (stat.isDirectory()) {
    const entries = readdirSync(absolutePath, { withFileTypes: true }).sort(
      (left, right) => left.name.localeCompare(right.name),
    );
    for (const entry of entries) {
      if (entry.isDirectory() || entry.isFile()) {
        collectMarkdownFiles(path.join(absolutePath, entry.name), files, errors);
      }
    }
    return;
  }

  if (stat.isFile() && path.extname(absolutePath).toLowerCase() === ".md") {
    files.add(absolutePath);
  }
}

function parseDestination(rawDestination) {
  const value = rawDestination.trim();
  if (value.startsWith("<")) {
    const closingBracket = value.indexOf(">");
    return closingBracket >= 0 ? value.slice(1, closingBracket) : null;
  }

  let destination = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (/\s/.test(character)) {
      break;
    }
    if (
      character === "\\" &&
      index + 1 < value.length &&
      /[\\`*{}[\]()#+\-.!_>]/.test(value[index + 1])
    ) {
      destination += value[index + 1];
      index += 1;
      continue;
    }
    destination += character;
  }
  return destination || null;
}

function markdownDestinations(content) {
  const destinations = [];
  const lines = content.replace(/\r\n?/g, "\n").split("\n");
  let fence = null;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    const fenceMatch = line.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (fenceMatch) {
      const marker = fenceMatch[1];
      if (fence === null) {
        fence = marker[0];
      } else if (marker[0] === fence) {
        fence = null;
      }
      continue;
    }
    if (fence !== null) {
      continue;
    }

    const searchableLine = line.replace(/(`+)(.*?)\1/g, (match) =>
      " ".repeat(match.length),
    );
    const inlinePattern = /!?\[[^\]\r\n]*\]\(\s*(<[^>\r\n]+>|[^)\r\n]+)\s*\)/g;
    for (const match of searchableLine.matchAll(inlinePattern)) {
      destinations.push({ raw: match[1], line: lineIndex + 1 });
    }

    const definitionMatch = searchableLine.match(
      /^\s{0,3}\[[^\]\r\n]+\]:\s*(<[^>\r\n]+>|\S+)/,
    );
    if (definitionMatch) {
      destinations.push({ raw: definitionMatch[1], line: lineIndex + 1 });
    }
  }

  return destinations;
}

const files = new Set();
const errors = [];
for (const input of inputs) {
  collectMarkdownFiles(input, files, errors);
}

const markdownFiles = [...files].sort((left, right) =>
  left.localeCompare(right),
);
if (markdownFiles.length === 0) {
  errors.push({
    file: null,
    line: 0,
    target: null,
    reason: "no Markdown files were found",
  });
}

let localLinks = 0;
let skippedLinks = 0;
for (const markdownFile of markdownFiles) {
  const content = readFileSync(markdownFile, "utf8");
  for (const destination of markdownDestinations(content)) {
    const target = parseDestination(destination.raw);
    if (target === null) {
      errors.push({
        file: displayPath(markdownFile),
        line: destination.line,
        target: destination.raw,
        reason: "link destination is malformed",
      });
      continue;
    }

    const isWindowsAbsolute = /^[A-Za-z]:[\\/]/.test(target);
    const isUrl =
      !isWindowsAbsolute &&
      (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(target) || target.startsWith("//"));
    if (target.startsWith("#") || target.startsWith("?") || isUrl) {
      skippedLinks += 1;
      continue;
    }

    localLinks += 1;
    if (isWindowsAbsolute || path.isAbsolute(target)) {
      errors.push({
        file: displayPath(markdownFile),
        line: destination.line,
        target,
        reason: "local link must be relative",
      });
      continue;
    }

    const pathPart = target.replace(/[?#].*$/, "");
    let decodedPath;
    try {
      decodedPath = decodeURIComponent(pathPart);
    } catch {
      errors.push({
        file: displayPath(markdownFile),
        line: destination.line,
        target,
        reason: "link path contains invalid percent encoding",
      });
      continue;
    }

    const resolvedPath = path.resolve(path.dirname(markdownFile), decodedPath);
    if (!existsSync(resolvedPath)) {
      errors.push({
        file: displayPath(markdownFile),
        line: destination.line,
        target,
        reason: `target does not exist: ${displayPath(resolvedPath)}`,
      });
    }
  }
}

const result = {
  ok: errors.length === 0,
  checkedFiles: markdownFiles.length,
  localLinks,
  skippedLinks,
  errors,
};

if (jsonOutput) {
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} else if (result.ok) {
  process.stdout.write(
    `Markdown link check passed: ${result.checkedFiles} file(s), ` +
      `${result.localLinks} local link(s), ${result.skippedLinks} skipped link(s).\n`,
  );
} else {
  for (const error of result.errors) {
    const location = error.file
      ? `${error.file}${error.line > 0 ? `:${error.line}` : ""}`
      : "<inputs>";
    process.stderr.write(
      `${location}: ${error.reason}${error.target ? ` (${error.target})` : ""}\n`,
    );
  }
  process.stderr.write(
    `Markdown link check failed: ${result.errors.length} error(s).\n`,
  );
}

process.exitCode = result.ok ? 0 : 1;
