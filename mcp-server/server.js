import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

const DEFAULT_BASE_URL = 'https://anubhavg-icpl.github.io/appControlBusiness';
const SOURCE_MODE = process.env.ACFB_SOURCE_MODE || 'remote';
const BASE_URL = (process.env.ACFB_BASE_URL || DEFAULT_BASE_URL).replace(/\/$/, '');
const WELCOME_BANNER = 'End 2 end welcome to Anubhav Gain\'s wizard of WDAC 🪄, because apparently regular documentation was too easy.';

function localPath(relativePath) {
  return path.join(repoRoot, relativePath);
}

async function readJson(relativePath) {
  if (SOURCE_MODE === 'local') {
    return JSON.parse(await fs.readFile(localPath(relativePath), 'utf8'));
  }

  const response = await fetch(`${BASE_URL}/${relativePath}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${relativePath}: HTTP ${response.status}`);
  }
  return response.json();
}

async function readText(relativePath) {
  if (SOURCE_MODE === 'local') {
    return fs.readFile(localPath(relativePath), 'utf8');
  }

  const response = await fetch(`${BASE_URL}/${relativePath}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch ${relativePath}: HTTP ${response.status}`);
  }
  return response.text();
}

function normalize(value) {
  return String(value || '').toLowerCase();
}

function scoreDocument(doc, tokens) {
  if (!tokens.length) return 1;

  const title = normalize(doc.title);
  const description = normalize(doc.description);
  const tags = normalize((doc.tags || []).join(' '));
  const headings = normalize((doc.headings || []).map(item => item.title).join(' '));
  const excerpt = normalize(doc.excerpt);
  const text = normalize(doc.text);

  let total = 0;
  for (const token of tokens) {
    let tokenScore = 0;
    if (title.includes(token)) tokenScore += 12;
    if (description.includes(token)) tokenScore += 8;
    if (tags.includes(token)) tokenScore += 7;
    if (headings.includes(token)) tokenScore += 6;
    if (excerpt.includes(token)) tokenScore += 4;
    if (text.includes(token)) tokenScore += 2;
    if (!tokenScore) return 0;
    total += tokenScore;
  }
  return total;
}

function toTextContent(text) {
  return {
    content: [
      {
        type: 'text',
        text
      }
    ]
  };
}

const server = new McpServer({
  name: 'app-control-business-mcp',
  version: '0.1.0'
});

server.tool(
  'site_info',
  'Return the high-level corpus metadata and generated asset entry points.',
  async () => {
    const resources = await readJson('ai/resources.json');
    return {
      content: [
        {
          type: 'text',
          text: `${WELCOME_BANNER}\n\n${JSON.stringify(resources, null, 2)}`
        }
      ]
    };
  }
);

server.tool(
  'list_documents',
  'List corpus documents from the generated search index, optionally filtering by kind.',
  {
    kind: z.string().optional(),
    limit: z.number().int().min(1).max(200).default(25)
  },
  async ({ kind, limit }) => {
    const payload = await readJson('ai/search-index.json');
    const docs = payload.documents
      .filter(doc => !kind || doc.kind === kind)
      .slice(0, limit)
      .map(doc => ({
        title: doc.title,
        path: doc.path,
        kind: doc.kind,
        url: doc.url,
        description: doc.description
      }));
    return toTextContent(JSON.stringify(docs, null, 2));
  }
);

server.tool(
  'search_docs',
  'Run a relevance-ranked search over titles, descriptions, tags, headings, excerpts, and full text.',
  {
    query: z.string().min(1),
    kind: z.string().optional(),
    limit: z.number().int().min(1).max(50).default(10)
  },
  async ({ query, kind, limit }) => {
    const tokens = query.toLowerCase().split(/\s+/).map(token => token.trim()).filter(Boolean);
    const payload = await readJson('ai/search-index.json');
    const results = payload.documents
      .map(doc => ({ ...doc, score: scoreDocument(doc, tokens) }))
      .filter(doc => doc.score > 0)
      .filter(doc => !kind || doc.kind === kind)
      .sort((a, b) => b.score - a.score || a.title.localeCompare(b.title))
      .slice(0, limit)
      .map(doc => ({
        title: doc.title,
        path: doc.path,
        url: doc.url,
        kind: doc.kind,
        score: doc.score,
        description: doc.description,
        excerpt: doc.excerpt,
        tags: doc.tags
      }));
    return toTextContent(JSON.stringify(results, null, 2));
  }
);

server.tool(
  'get_document',
  'Fetch a document by relative path from the published site or local checkout.',
  {
    path: z.string().min(1)
  },
  async ({ path: relativePath }) => {
    const cleanedPath = relativePath.replace(/^\/+/, '');
    const text = await readText(cleanedPath);
    return toTextContent(text);
  }
);

server.tool(
  'get_frontmatter',
  'Fetch the generated JSON frontmatter export for a corpus document.',
  {
    path: z.string().min(1)
  },
  async ({ path: relativePath }) => {
    const cleanedPath = relativePath.replace(/^\/+/, '').replace(/\.md$/, '.json');
    const exportPath = `ai/frontmatter/${cleanedPath}`;
    const payload = await readJson(exportPath);
    return toTextContent(JSON.stringify(payload, null, 2));
  }
);

server.tool(
  'get_updates',
  'Return the machine-readable JSON change feed derived from docs/log.md.',
  async () => {
    const payload = await readJson('ai/updates.json');
    return toTextContent(JSON.stringify(payload, null, 2));
  }
);

const transport = new StdioServerTransport();
console.error(WELCOME_BANNER);
await server.connect(transport);