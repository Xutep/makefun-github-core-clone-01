// forge: a standalone GitHub-compatible git forge. One process, its own in-memory
// store, no UI, no outside service, no git binary. Serves git smart HTTP
// (upload-pack v2, receive-pack v0), REST v3, GraphQL v4 and MCP over one HTTP
// server. Node 22 standard library only.
//
// The token owner (the "viewer") is not handed to this process by name, only by
// bearer token. The suite's scenario is a pure function of one published constant
// seed, so the viewer login is re-derived here from that seed with the same
// deterministic generator the kit publishes. That is how the forge knows which
// login owns the repositories it creates, and which login is a stranger.

import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';

// ---------------------------------------------------------------------------
// The scenario seed and its deterministic generator (published in the kit).
// ---------------------------------------------------------------------------

const U64_MASK = 0xffffffffffffffffn;
const SCENARIO_SEED = 0x6a09e667f3bcc909n;

function fnv1a64(text: string): bigint {
  let hash = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= BigInt(text.charCodeAt(i));
    hash = (hash * 0x100000001b3n) & U64_MASK;
  }
  return hash;
}

function mix64(value: bigint): bigint {
  let z = (value + 0x9e3779b97f4a7c15n) & U64_MASK;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64_MASK;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64_MASK;
  return (z ^ (z >> 31n)) & U64_MASK;
}

/** xorshift64*: the seeded stream the scenario draws every name from. */
class Rng {
  #state: bigint;
  constructor(seed: bigint) {
    const masked = seed & U64_MASK;
    this.#state = masked === 0n ? SCENARIO_SEED : masked;
  }
  nextU64(): bigint {
    let x = this.#state;
    x = (x ^ (x >> 12n)) & U64_MASK;
    x = (x ^ (x << 25n)) & U64_MASK;
    x = (x ^ (x >> 27n)) & U64_MASK;
    this.#state = x;
    return (x * 0x2545f4914f6cdd1dn) & U64_MASK;
  }
  nextU32(): number {
    return Number(this.nextU64() >> 32n);
  }
  nextInt(maxExclusive: number): number {
    if (maxExclusive === 1) return 0;
    const range = 4_294_967_296;
    const limit = range - (range % maxExclusive);
    for (;;) {
      const value = this.nextU32();
      if (value < limit) return value % maxExclusive;
    }
  }
  pick<T>(items: readonly T[]): T {
    return items[this.nextInt(items.length)] as T;
  }
}

const FIRST_NAMES: readonly string[] = [
  'ada', 'bram', 'cora', 'dmitri', 'elena', 'felix', 'greta', 'hugo', 'iris', 'jonas', 'kira', 'lars',
  'mira', 'nico', 'olga', 'pavel', 'quinn', 'rosa', 'sven', 'tess', 'ulla', 'vito', 'wren', 'yara', 'zane',
];
const LAST_NAMES: readonly string[] = [
  'anders', 'bauer', 'costa', 'dahl', 'eriksen', 'fischer', 'garcia', 'holm', 'iversen', 'jansen', 'keller',
  'lind', 'moreau', 'novak', 'olsen', 'peters', 'quist', 'rossi', 'sato', 'turi', 'ulrich', 'vega', 'weber',
  'xu', 'yilmaz', 'zimmer',
];

interface ScenarioUser {
  id: number;
  login: string;
  name: string;
  email: string;
}

/** The scenario's users, in order: [0] is the viewer, [2] the stranger. */
function scenarioUsers(): ScenarioUser[] {
  const rng = new Rng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>();
  const users: ScenarioUser[] = [];
  for (let i = 0; i < 12; i += 1) {
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    let login = `${first}${last}`.replace(/[^a-z0-9-]/g, '');
    let suffix = 2;
    while (used.has(login)) {
      login = `${first}${last}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
    users.push({ id: 1000 + i, login, name: `${first} ${last}`, email: `${login}@example.invalid` });
  }
  return users;
}

const USERS = scenarioUsers();
const VIEWER: ScenarioUser = USERS[0] as ScenarioUser;
const STRANGER_LOGIN: string = (USERS[2] as ScenarioUser).login;

// ---------------------------------------------------------------------------
// Small shared helpers.
// ---------------------------------------------------------------------------

export const ZERO_OID = '0'.repeat(40);
const FORGE_VERSION = '1.0.0';
const FORGE_AGENT = 'forge/1.0';
const EPOCH_BASE = 1_735_689_600;

let clockSeq = 0;
/** A deterministic timestamp (seconds): never the wall clock, so state replays. */
function nextTimestamp(): number {
  clockSeq += 1;
  return EPOCH_BASE + clockSeq;
}
function isoOf(ts: number): string {
  return new Date(ts * 1000).toISOString();
}

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function b64encode(data: Buffer): string {
  return data.toString('base64');
}
function b64decode(text: string): Buffer | null {
  const clean = text.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 !== 0) return null;
  try {
    return Buffer.from(clean, 'base64');
  } catch {
    return null;
  }
}

/** Opaque, stable Relay-style global id: base64url of a typed path. */
function globalId(kind: string, parts: readonly (string | number)[]): string {
  return Buffer.from(`${kind}:${parts.join(':')}`, 'utf8').toString('base64url');
}
function parseGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64url').toString('utf8');
    const [kind, ...parts] = text.split(':');
    if (kind === undefined || kind === '' || parts.length === 0) return null;
    return { kind, parts };
  } catch {
    return null;
  }
}

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

export function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

export function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) break;
    const mode = data.subarray(offset, space).toString('ascii');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: { name: string; isDir: boolean }, b: { name: string; isDir: boolean }): number {
  const ka = a.name + (a.isDir ? '/' : '');
  const kb = b.name + (b.isDir ? '/' : '');
  if (ka < kb) return -1;
  if (ka > kb) return 1;
  return 0;
}

export function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) =>
    compareTreeNames({ name: a.name, isDir: a.mode === '40000' }, { name: b.name, isDir: b.mode === '40000' }),
  );
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

export function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

export function buildCommit(fields: { tree: string; parents: readonly string[]; author: string; committer: string; message: string }): Buffer {
  const head: string[] = [`tree ${fields.tree}`];
  for (const parent of fields.parents) head.push(`parent ${parent}`);
  head.push(`author ${fields.author}`, `committer ${fields.committer}`);
  const message = fields.message.endsWith('\n') ? fields.message : `${fields.message}\n`;
  return Buffer.from(`${head.join('\n')}\n\n${message}`, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

/** Every object id reachable from `roots` (commits, trees, blobs, tags). */
function reachableObjects(objects: Map<string, GitObject>, roots: readonly string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = objects.get(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      stack.push(commit.tree);
      for (const parent of commit.parents) stack.push(parent);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) stack.push(entry.oid);
    } else if (object.type === 'tag') {
      stack.push(parseTag(object.data).object);
    }
  }
  return seen;
}

/** True when `ancestor` is reachable from `descendant` by parent links. */
function isAncestor(objects: Map<string, GitObject>, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const stack = [descendant];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) stack.push(parent);
  }
  return false;
}

/** A common ancestor of two commits (nearest by breadth-first walk), or null. */
function mergeBase(objects: Map<string, GitObject>, a: string, b: string): string | null {
  const ancestorsA = new Set<string>();
  const stackA = [a];
  while (stackA.length > 0) {
    const oid = stackA.pop() as string;
    if (ancestorsA.has(oid)) continue;
    ancestorsA.add(oid);
    const object = objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) stackA.push(parent);
  }
  const queue = [b];
  const seen = new Set<string>();
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (ancestorsA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return null;
}

/** Flatten a commit's tree to path -> {oid, mode}. */
function flattenTree(objects: Map<string, GitObject>, treeOid: string, prefix = ''): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, path: string): void => {
    const object = objects.get(oid);
    if (object === undefined || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const full = path === '' ? entry.name : `${path}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, full);
      else out.set(full, { oid: entry.oid, mode: entry.mode });
    }
  };
  walk(treeOid, prefix);
  return out;
}

// ---------------------------------------------------------------------------
// Packfiles: plain objects only (no deltas), version 2, SHA-1 trailer.
// ---------------------------------------------------------------------------

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const typeNum = type === 'commit' ? 1 : type === 'tree' ? 2 : type === 'blob' ? 3 : 4;
  const bytes: number[] = [];
  let remaining = size;
  let first = true;
  for (;;) {
    let byte: number;
    if (first) {
      byte = (typeNum << 4) | (remaining & 0x0f);
      remaining >>= 4;
      first = false;
    } else {
      byte = remaining & 0x7f;
      remaining >>= 7;
    }
    if (remaining > 0) byte |= 0x80;
    bytes.push(byte);
    if (remaining === 0) break;
  }
  return Buffer.from(bytes);
}

export function writePack(entries: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK'), Buffer.alloc(4), Buffer.alloc(4)];
  parts[1]?.writeUInt32BE(2, 0);
  parts[2]?.writeUInt32BE(entries.length, 0);
  for (const entry of entries) {
    parts.push(writePackObjectHeader(entry.type, entry.data.length));
    parts.push(deflateSync(entry.data, { level: 6 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

interface PackEntry {
  type: GitObjectType;
  data: Buffer;
  oid: string;
}

/** Read a pack of plain objects. Throws on a bad header, a bad checksum or a delta. */
export function readPack(pack: Buffer): PackEntry[] {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const expected = sha1Hex(pack.subarray(0, pack.length - 20));
  const actual = pack.subarray(pack.length - 20).toString('hex');
  if (expected !== actual) throw new Error('pack trailer checksum mismatch');
  const entries: PackEntry[] = [];
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    let byte = pack[offset] as number;
    offset += 1;
    const typeNum = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = pack[offset] as number;
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    const type: GitObjectType | null =
      typeNum === 1 ? 'commit' : typeNum === 2 ? 'tree' : typeNum === 3 ? 'blob' : typeNum === 4 ? 'tag' : null;
    if (type === null) throw new Error(`unsupported pack object type ${typeNum} (deltas are not accepted)`);
    const inflated = inflateSync(pack.subarray(offset));
    if (inflated.length !== size) throw new Error('pack object size mismatch');
    // Node's inflateSync stops at the end of the first zlib stream and ignores the
    // bytes after it, so the stream's length is found by binary search: the smallest
    // prefix of the remainder that inflates to exactly `size` bytes.
    let consumed = 0;
    {
      let lo = 1;
      let hi = pack.length - offset;
      while (lo < hi) {
        const mid = Math.floor((lo + hi) / 2);
        try {
          const trial = inflateSync(pack.subarray(offset, offset + mid));
          if (trial.length === size) {
            hi = mid;
          } else {
            lo = mid + 1;
          }
        } catch {
          lo = mid + 1;
        }
      }
      consumed = lo;
    }
    offset += consumed;
    entries.push({ type, data: inflated, oid: hashObject(type, inflated) });
  }
  return entries;
}

// ---------------------------------------------------------------------------
// pkt-line codec.
// ---------------------------------------------------------------------------

const PKT_MAX = 65520;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  if (data.length + 4 > PKT_MAX) throw new Error('pkt-line too long');
  const header = Buffer.alloc(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}
function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}
function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}
function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(pktFlush());
    else if (item === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' };

/** Decode every pkt-line in a fully-buffered body. Throws on malformed framing. */
function decodePktLines(body: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let offset = 0;
  while (offset < body.length) {
    if (offset + 4 > body.length) throw new Error('truncated pkt-line header');
    const header = body.subarray(offset, offset + 4).toString('ascii');
    if (header === '0000') {
      out.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (header === '0001') {
      out.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (header === '0002') {
      out.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    const length = parseInt(header, 16);
    if (!Number.isFinite(length) || length < 4 || offset + length > body.length) throw new Error('bad pkt-line length');
    out.push({ kind: 'data', payload: body.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return out;
}

/** Split a decoded stream into its pkt-line text lines (data packets only, in order). */
function pktTextLines(packets: readonly Pkt[]): string[] {
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  return lines;
}

// ---------------------------------------------------------------------------
// The store: repositories, issues, pull requests, comments, labels.
// ---------------------------------------------------------------------------

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  createdAt: string;
  updatedAt: string;
}

interface Comment {
  id: number;
  body: string;
  createdAt: string;
}

interface PullRequest {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string;
  mergeCommitSha: string;
  seq: number;
  createdAt: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  seq: number;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Map<number, Issue>;
  nextIssue: number;
  labels: Map<string, { name: string; color: string; id: number }>;
  pulls: Map<number, PullRequest>;
  nextPull: number;
  comments: Map<number, Comment[]>;
  nextCommentId: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextGlobalCommentId = 1;
let nextGlobalLabelId = 1;
let nextIssueDbId = 100000;
let nextPullDbId = 200000;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function createRepoRecord(name: string, isPrivate: boolean, description: string, defaultBranch: string): Repo {
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner: VIEWER.login,
    description,
    isPrivate,
    defaultBranch: defaultBranch === '' ? 'main' : defaultBranch,
    seq: nextRepoId,
    objects: new Map(),
    refs: new Map(),
    issues: new Map(),
    nextIssue: 1,
    labels: new Map(),
    pulls: new Map(),
    nextPull: 1,
    comments: new Map(),
    nextCommentId: 1,
  };
  nextRepoId += 1;
  repos.set(repoKey(VIEWER.login, name), repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER.login) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}

function refTip(repo: Repo, ref: string): string | null {
  return repo.refs.get(ref) ?? null;
}

function branchTip(repo: Repo, branch: string): string | null {
  return repo.refs.get(`refs/heads/${branch}`) ?? null;
}

/** The commit a ref name (branch, full ref, or sha) resolves to, or null. */
function resolveRefToCommit(repo: Repo, ref: string): string | null {
  if (isOid(ref)) {
    const object = repo.objects.get(ref);
    if (object === undefined) return null;
    if (object.type === 'commit') return ref;
    if (object.type === 'tag') {
      const target = parseTag(object.data).object;
      const targetObject = repo.objects.get(target);
      return targetObject !== undefined && targetObject.type === 'commit' ? target : null;
    }
    return null;
  }
  const direct = repo.refs.get(ref);
  if (direct !== undefined) return derefToCommit(repo, direct);
  const asBranch = repo.refs.get(`refs/heads/${ref}`);
  if (asBranch !== undefined) return derefToCommit(repo, asBranch);
  const asTag = repo.refs.get(`refs/tags/${ref}`);
  if (asTag !== undefined) return derefToCommit(repo, asTag);
  return null;
}

function derefToCommit(repo: Repo, oid: string): string | null {
  const object = repo.objects.get(oid);
  if (object === undefined) return null;
  if (object.type === 'commit') return oid;
  if (object.type === 'tag') return derefToCommit(repo, parseTag(object.data).object);
  return null;
}

/** Build trees for a flat path -> blob-oid map, storing every tree; return the root oid. */
export function buildTreesForFiles(repo: Repo, files: Map<string, string>): string {
  interface Node {
    blobs: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const root: Node = { blobs: new Map(), dirs: new Map() };
  for (const [path, oid] of files) {
    const segments = path.split('/').filter((segment) => segment !== '');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const segment = segments[i] as string;
      let child = node.dirs.get(segment);
      if (child === undefined) {
        child = { blobs: new Map(), dirs: new Map() };
        node.dirs.set(segment, child);
      }
      node = child;
    }
    node.blobs.set(segments[segments.length - 1] as string, oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.blobs) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/** Store a blob's bytes, returning its oid. */
function storeBlob(repo: Repo, data: Buffer): string {
  const oid = hashObject('blob', data);
  repo.objects.set(oid, { type: 'blob', data });
  return oid;
}

/** Create a commit on top of `parent` (or root) with the given flat file map. */
function createFileCommit(
  repo: Repo,
  files: Map<string, string>,
  parents: readonly string[],
  message: string,
): string {
  const treeOid = buildTreesForFiles(repo, files);
  const ts = nextTimestamp();
  const ident = `${VIEWER.login} <${VIEWER.email}> ${ts} +0000`;
  const commit = buildCommit({ tree: treeOid, parents, author: ident, committer: ident, message });
  const oid = hashObject('commit', commit);
  repo.objects.set(oid, { type: 'commit', data: commit });
  return oid;
}

/** The flat file map of a commit's tree. */
function filesAtCommit(repo: Repo, commitOid: string): Map<string, string> {
  const commit = repo.objects.get(commitOid);
  if (commit === undefined || commit.type !== 'commit') return new Map();
  const flat = flattenTree(repo.objects, parseCommit(commit.data).tree);
  const out = new Map<string, string>();
  for (const [path, entry] of flat) out.set(path, entry.oid);
  return out;
}

interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  oldOid: string | null;
  newOid: string | null;
  additions: number;
  deletions: number;
}

function countLines(data: Buffer | null): number {
  if (data === null || data.length === 0) return 0;
  const text = data.toString('utf8');
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines.length;
}

/** Diff two flat file maps (base -> head), with rough line counts. */
function diffFileMaps(repo: Repo, base: Map<string, string>, head: Map<string, string>): FileChange[] {
  const changes: FileChange[] = [];
  const paths = new Set<string>([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const oldOid = base.get(path) ?? null;
    const newOid = head.get(path) ?? null;
    if (oldOid === newOid) continue;
    const oldData = oldOid === null ? null : (repo.objects.get(oldOid)?.data ?? null);
    const newData = newOid === null ? null : (repo.objects.get(newOid)?.data ?? null);
    if (oldOid === null) {
      changes.push({ path, status: 'added', oldOid, newOid, additions: countLines(newData), deletions: 0 });
    } else if (newOid === null) {
      changes.push({ path, status: 'removed', oldOid, newOid, additions: 0, deletions: countLines(oldData) });
    } else {
      // Rough line diff: lines present in one version but not the other (multiset).
      const oldLines = (oldData ?? Buffer.alloc(0)).toString('utf8').split('\n');
      const newLines = (newData ?? Buffer.alloc(0)).toString('utf8').split('\n');
      const oldCounts = new Map<string, number>();
      for (const line of oldLines) oldCounts.set(line, (oldCounts.get(line) ?? 0) + 1);
      let additions = 0;
      for (const line of newLines) {
        const remaining = oldCounts.get(line) ?? 0;
        if (remaining > 0) oldCounts.set(line, remaining - 1);
        else additions += 1;
      }
      let deletions = 0;
      for (const remaining of oldCounts.values()) deletions += remaining;
      changes.push({ path, status: 'modified', oldOid, newOid, additions, deletions });
    }
  }
  return changes;
}

/** Squash-merge analysis: returns the merged file map, or null on conflict. */
function squashMergeFiles(
  repo: Repo,
  baseTip: string,
  headTip: string,
): { files: Map<string, string>; conflict: boolean } {
  const base = mergeBase(repo.objects, baseTip, headTip);
  const baseFiles = base === null ? new Map<string, string>() : filesAtCommit(repo, base);
  const tipFiles = filesAtCommit(repo, baseTip);
  const headFiles = filesAtCommit(repo, headTip);
  const headChanges = diffFileMaps(repo, baseFiles, headFiles);
  const tipChanges = new Map<string, FileChange>();
  for (const change of diffFileMaps(repo, baseFiles, tipFiles)) tipChanges.set(change.path, change);
  const merged = new Map<string, string>(tipFiles);
  for (const change of headChanges) {
    const tipChange = tipChanges.get(change.path);
    if (tipChange !== undefined && tipChange.newOid !== change.newOid) {
      return { files: merged, conflict: true };
    }
    if (change.newOid === null) merged.delete(change.path);
    else merged.set(change.path, change.newOid);
  }
  return { files: merged, conflict: false };
}

/** Whether a pull request can merge cleanly (same analysis as the merge itself). */
function pullIsMergeable(repo: Repo, pull: PullRequest): 'MERGEABLE' | 'CONFLICTING' {
  if (pull.state !== 'open') return 'UNKNOWN' as never;
  const baseTip = branchTip(repo, pull.baseRef);
  const headTip = branchTip(repo, pull.headRef);
  if (baseTip === null || headTip === null) return 'UNKNOWN' as never;
  const result = squashMergeFiles(repo, baseTip, headTip);
  return result.conflict ? 'CONFLICTING' : 'MERGEABLE';
}

// ---------------------------------------------------------------------------
// Git smart HTTP.
// ---------------------------------------------------------------------------

interface AdvertisedRef {
  oid: string;
  name: string;
  peeled?: string;
}

/** All refs of a repo, HEAD first, then branches, then tags. */
function advertisedRefs(repo: Repo): AdvertisedRef[] {
  const refs: AdvertisedRef[] = [];
  const tip = branchTip(repo, repo.defaultBranch);
  if (tip !== null) refs.push({ oid: tip, name: 'HEAD' });
  const names = [...repo.refs.keys()].sort();
  for (const name of names) {
    const oid = repo.refs.get(name) as string;
    const object = repo.objects.get(oid);
    let peeled: string | undefined;
    if (object !== undefined && object.type === 'tag') {
      const target = derefToCommit(repo, oid);
      if (target !== null) peeled = target;
    }
    refs.push({ oid, name, peeled });
  }
  return refs;
}

function uploadPackV0Caps(repo: Repo): string {
  return [
    'side-band-64k',
    'thin-pack',
    'ofs-delta',
    'shallow',
    `agent=${FORGE_AGENT}`,
    `symref=HEAD:refs/heads/${repo.defaultBranch}`,
  ].join(' ');
}

function receivePackCaps(repo: Repo): string {
  return [
    'report-status',
    'report-status-v2',
    'side-band-64k',
    'delete-refs',
    'ofs-delta',
    `agent=${FORGE_AGENT}`,
    `symref=HEAD:refs/heads/${repo.defaultBranch}`,
  ].join(' ');
}

/** The info/refs advertisement body for a service, in the requested protocol. */
function advertisementBody(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack', protocol: 2 | 0): Buffer {
  if (protocol === 2) {
    return pktLines([
      'version 2\n',
      `agent=${FORGE_AGENT}\n`,
      'ls-refs=unborn\n',
      'fetch=shallow wait-for-done\n',
      'object-format=sha1\n',
      'flush',
    ]);
  }
  const serviceLine = `# service=${service}\n`;
  const caps = service === 'git-upload-pack' ? uploadPackV0Caps(repo) : receivePackCaps(repo);
  const refs = advertisedRefs(repo);
  const lines: (string | 'flush')[] = [serviceLine, 'flush'];
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    let first = true;
    for (const ref of refs) {
      if (ref.name === 'HEAD') continue;
      const suffix = first ? `\0${caps}` : '';
      first = false;
      lines.push(`${ref.oid} ${ref.name}${suffix}\n`);
      if (ref.peeled !== undefined) lines.push(`${ref.peeled} ${ref.name}^{}\n`);
    }
  }
  lines.push('flush');
  return pktLines(lines);
}

interface FetchSelection {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
  wantedRefs: { oid: string; ref: string }[];
}

/**
 * Which objects a fetch sends: the closure of the wanted commits, cut off at the
 * depth limit and at commits the client already holds (unless they are the
 * client's own shallow boundaries, whose history it does not have).
 */
function selectFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  depth: number | null,
  shallowIn: readonly string[],
): FetchSelection {
  const shallowInSet = new Set(shallowIn);
  const heldKnown = new Set(haves.filter((oid) => !shallowInSet.has(oid)));
  // Resolve each want to its commit (tags dereference to their target).
  const wantCommits: { want: string; commit: string }[] = [];
  for (const want of wants) {
    const commit = derefToCommit(repo, want);
    if (commit !== null) wantCommits.push({ want, commit });
  }
  // Breadth-first walk from the wanted commits, honouring the depth limit.
  const included = new Set<string>();
  const distance = new Map<string, number>();
  const queue: string[] = [];
  for (const { commit } of wantCommits) {
    if (!included.has(commit) && !heldKnown.has(commit)) {
      included.add(commit);
      distance.set(commit, 0);
      queue.push(commit);
    }
  }
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    const dist = distance.get(oid) as number;
    if (depth !== null && dist + 1 >= depth) continue;
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (included.has(parent) || heldKnown.has(parent)) continue;
      included.add(parent);
      distance.set(parent, dist + 1);
      queue.push(parent);
    }
  }
  // New shallow boundaries: included commits whose parent is not included.
  const shallow: string[] = [];
  for (const oid of included) {
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    const parents = parseCommit(object.data).parents;
    if (parents.some((parent) => !included.has(parent))) shallow.push(oid);
  }
  // Old boundaries that are now fully known stop being shallow.
  const unshallow: string[] = [];
  for (const boundary of shallowIn) {
    if (!included.has(boundary)) continue;
    const object = repo.objects.get(boundary);
    if (object === undefined || object.type !== 'commit') continue;
    if (parseCommit(object.data).parents.every((parent) => included.has(parent))) unshallow.push(boundary);
  }
  // The object set: each included commit with its own tree closure (never the
  // commit's parents — a depth limit cuts the history off there), plus tag
  // objects the client asked for by id, minus what the client already holds.
  const sendAll = new Set<string>();
  const addTreeClosure = (treeOid: string): void => {
    const stack = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (sendAll.has(oid)) continue;
      const object = repo.objects.get(oid);
      if (object === undefined) continue;
      sendAll.add(oid);
      if (object.type === 'tree') {
        for (const entry of parseTree(object.data)) stack.push(entry.oid);
      }
    }
  };
  for (const oid of included) {
    sendAll.add(oid);
    const object = repo.objects.get(oid);
    if (object !== undefined && object.type === 'commit') addTreeClosure(parseCommit(object.data).tree);
  }
  for (const want of wants) {
    const object = repo.objects.get(want);
    if (object !== undefined && object.type === 'tag') sendAll.add(want);
  }
  const heldAll = reachableObjects(repo.objects, [...heldKnown]);
  const objects: GitObject[] = [];
  for (const oid of sendAll) {
    if (heldAll.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object !== undefined) objects.push(object);
  }
  // Deterministic pack order: commits first (parents before children is not
  // required for plain packs), then trees, then blobs, each by oid.
  const typeOrder = (type: GitObjectType): number => (type === 'commit' ? 0 : type === 'tag' ? 1 : type === 'tree' ? 2 : 3);
  const oidOf = new Map<GitObject, string>();
  for (const oid of sendAll) {
    if (heldAll.has(oid)) continue;
    const object = repo.objects.get(oid);
    if (object !== undefined) oidOf.set(object, oid);
  }
  objects.sort((a, b) => {
    const byType = typeOrder(a.type) - typeOrder(b.type);
    if (byType !== 0) return byType;
    const ao = oidOf.get(a) ?? '';
    const bo = oidOf.get(b) ?? '';
    return ao < bo ? -1 : ao > bo ? 1 : 0;
  });
  const wantedRefs: { oid: string; ref: string }[] = [];
  for (const want of wants) {
    for (const [name, oid] of repo.refs) {
      if (oid === want) wantedRefs.push({ oid: want, ref: name });
    }
  }
  return { objects, shallow, unshallow, wantedRefs };
}

/** Split bytes into sideband band-1 pkt-lines (payload <= 65516). */
function sidebandPackets(data: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const chunkSize = 32768;
  for (let offset = 0; offset < data.length; offset += chunkSize) {
    const chunk = data.subarray(offset, Math.min(data.length, offset + chunkSize));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return out;
}

interface V2FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
}

/** Parse a v2 fetch/ls-refs request body into its command and arguments. */
function parseV2Request(body: Buffer): { command: string; args: string[] } {
  const packets = decodePktLines(body);
  const lines = pktTextLines(packets);
  let command = '';
  const args: string[] = [];
  let pastDelim = false;
  for (const line of lines) {
    const trimmed = line.endsWith('\n') ? line.slice(0, -1) : line;
    if (trimmed.startsWith('command=')) {
      command = trimmed.slice('command='.length);
      continue;
    }
    if (trimmed.startsWith('agent=') || trimmed.startsWith('object-format=')) continue;
    args.push(trimmed);
  }
  void pastDelim;
  return { command, args };
}

function parseV2FetchArgs(args: readonly string[]): V2FetchRequest {
  const request: V2FetchRequest = { wants: [], haves: [], shallow: [], depth: null };
  for (const arg of args) {
    if (arg.startsWith('want ')) request.wants.push(arg.slice(5).trim());
    else if (arg.startsWith('have ')) request.haves.push(arg.slice(5).trim());
    else if (arg.startsWith('shallow ')) request.shallow.push(arg.slice(8).trim());
    else if (arg.startsWith('deepen ')) {
      const depth = Number(arg.slice(7).trim());
      if (Number.isFinite(depth) && depth > 0) request.depth = Math.trunc(depth);
    }
  }
  return request;
}

/** Answer a v2 ls-refs command. */
function handleLsRefsV2(repo: Repo, args: readonly string[]): Buffer {
  const peel = args.includes('peel');
  const symrefs = args.includes('symrefs');
  const unborn = args.includes('unborn');
  const prefixes: string[] = [];
  for (const arg of args) {
    if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
  }
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const lines: string[] = [];
  const defaultTip = branchTip(repo, repo.defaultBranch);
  if (defaultTip === null) {
    if (unborn && keep('HEAD')) {
      lines.push(`unborn HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`);
    }
  } else {
    if (keep('HEAD')) {
      lines.push(`${defaultTip} HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`);
    }
    for (const ref of advertisedRefs(repo)) {
      if (ref.name === 'HEAD') continue;
      if (!keep(ref.name)) continue;
      let line = `${ref.oid} ${ref.name}`;
      if (peel && ref.peeled !== undefined) line += ` peeled:${ref.peeled}`;
      lines.push(`${line}\n`);
    }
  }
  return pktLines([...lines, 'flush']);
}

/** Answer a v2 fetch command. */
function handleFetchV2(repo: Repo, args: readonly string[]): Buffer {
  const request = parseV2FetchArgs(args);
  if (request.wants.length === 0) return pktFlush();
  const selection = selectFetch(repo, request.wants, request.haves, request.depth, request.shallow);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), pktDelim());
  if (selection.shallow.length > 0 || selection.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of selection.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of selection.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(pktDelim());
  }
  if (selection.wantedRefs.length > 0) {
    parts.push(pktLine('wanted-refs\n'));
    for (const entry of selection.wantedRefs) parts.push(pktLine(`${entry.oid} ${entry.ref}\n`));
    parts.push(pktDelim());
  }
  if (selection.objects.length > 0) {
    const pack = writePack(selection.objects);
    parts.push(pktLine('packfile\n'));
    for (const packet of sidebandPackets(pack)) parts.push(packet);
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/** Parse a v0 fetch request: wants (with shallow/deepen) up to the first flush, then haves. */
function parseV0Fetch(body: Buffer): V2FetchRequest {
  const packets = decodePktLines(body);
  const request: V2FetchRequest = { wants: [], haves: [], shallow: [], depth: null };
  let section = 0;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      section += 1;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').trim();
    if (line.startsWith('want ')) {
      request.wants.push(line.slice(5).split(' ')[0] as string);
    } else if (line.startsWith('have ')) {
      request.haves.push(line.slice(5).trim());
    } else if (line.startsWith('shallow ')) {
      request.shallow.push(line.slice(8).trim());
    } else if (line.startsWith('deepen ')) {
      const depth = Number(line.slice(7).trim());
      if (Number.isFinite(depth) && depth > 0) request.depth = Math.trunc(depth);
    }
  }
  void section;
  return request;
}

/** Answer a v0 fetch. */
function handleFetchV0(repo: Repo, body: Buffer): Buffer {
  const request = parseV0Fetch(body);
  if (request.wants.length === 0) return pktFlush();
  const selection = selectFetch(repo, request.wants, request.haves, request.depth, request.shallow);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of selection.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of selection.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (selection.objects.length > 0) {
    const pack = writePack(selection.objects);
    for (const packet of sidebandPackets(pack)) parts.push(packet);
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/** Split a receive-pack body into its command lines and the pack that follows. */
function splitReceivePack(body: Buffer): { commands: string[]; pack: Buffer } {
  const commands: string[] = [];
  let offset = 0;
  while (offset < body.length) {
    if (offset + 4 > body.length) throw new Error('truncated pkt-line in push');
    const header = body.subarray(offset, offset + 4).toString('ascii');
    if (header === '0000') {
      offset += 4;
      break;
    }
    const length = parseInt(header, 16);
    if (!Number.isFinite(length) || length < 4 || offset + length > body.length) throw new Error('bad pkt-line in push');
    commands.push(body.subarray(offset + 4, offset + length).toString('utf8'));
    offset += length;
  }
  return { commands, pack: body.subarray(offset) };
}

/** Answer a receive-pack push. Returns the sideband-framed report-status body. */
function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  let unpackError: string | null = null;
  let commands: string[] = [];
  let pack = Buffer.alloc(0);
  try {
    const split = splitReceivePack(body);
    commands = split.commands;
    pack = split.pack;
  } catch (err) {
    unpackError = err instanceof Error ? err.message : 'bad request';
  }
  const reportLines: string[] = [];
  if (unpackError === null && pack.length > 0) {
    try {
      const entries = readPack(pack);
      for (const entry of entries) repo.objects.set(entry.oid, { type: entry.type, data: entry.data });
    } catch (err) {
      unpackError = err instanceof Error ? err.message : 'bad pack';
    }
  }
  if (unpackError !== null) {
    reportLines.push(`unpack ${unpackError}\n`);
  } else {
    reportLines.push('unpack ok\n');
    for (const rawLine of commands) {
      const line = rawLine.endsWith('\n') ? rawLine.slice(0, -1) : rawLine;
      const nul = line.indexOf('\0');
      const clean = nul >= 0 ? line.slice(0, nul) : line;
      const parts = clean.split(' ');
      if (parts.length < 3) {
        reportLines.push(`ng ${parts[2] ?? 'refs/heads/main'} bad command\n`);
        continue;
      }
      const [oldOid, newOid, ref] = parts as [string, string, string];
      const current = repo.refs.get(ref);
      if (newOid === ZERO_OID) {
        if (current === undefined) reportLines.push(`ng ${ref} remote ref does not exist\n`);
        else if (oldOid !== current) reportLines.push(`ng ${ref} non-fast-forward\n`);
        else {
          repo.refs.delete(ref);
          reportLines.push(`ok ${ref}\n`);
        }
      } else if (oldOid === ZERO_OID) {
        if (current !== undefined) reportLines.push(`ng ${ref} already exists\n`);
        else if (!repo.objects.has(newOid)) reportLines.push(`ng ${ref} missing object\n`);
        else {
          repo.refs.set(ref, newOid);
          reportLines.push(`ok ${ref}\n`);
        }
      } else {
        if (current === undefined) reportLines.push(`ng ${ref} remote ref does not exist\n`);
        else if (oldOid !== current) reportLines.push(`ng ${ref} non-fast-forward\n`);
        else if (!repo.objects.has(newOid)) reportLines.push(`ng ${ref} missing object\n`);
        else if (!isAncestor(repo.objects, oldOid, newOid)) reportLines.push(`ng ${ref} non-fast-forward\n`);
        else {
          repo.refs.set(ref, newOid);
          reportLines.push(`ok ${ref}\n`);
        }
      }
    }
  }
  const report = pktLines(reportLines);
  const parts: Buffer[] = [];
  for (let offset = 0; offset < report.length; offset += 32768) {
    const chunk = report.subarray(offset, Math.min(report.length, offset + 32768));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// HTTP plumbing: request ids, auth, JSON answers.
// ---------------------------------------------------------------------------

const SHOP_TOKEN: string = process.env.MAKEFUN_SHOP_TOKEN ?? '';
let requestCounter = 0;

function nextRequestId(): string {
  requestCounter += 1;
  return requestCounter.toString(16).padStart(16, '0');
}

function isAuthorized(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const token = header.slice('Bearer '.length);
  if (token === '') return false;
  if (SHOP_TOKEN === '') return true;
  return token === SHOP_TOKEN;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(),
    ...extra,
  });
  res.end(text);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'x-github-request-id': nextRequestId() });
  res.end();
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseQuery(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

function pathSegments(req: IncomingMessage): string[] {
  try {
    const pathname = new URL(req.url ?? '/', 'http://entry').pathname;
    return pathname.split('/').filter((segment) => segment !== '').map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });
  } catch {
    return [];
  }
}

function absoluteUrl(req: IncomingMessage, pathname: string, query: string): string {
  const host = req.headers.host ?? 'localhost';
  return `http://${host}${pathname}${query === '' ? '' : `?${query}`}`;
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const perPage = Math.min(100, Math.max(1, Number(query.get('per_page') ?? '30') || 30));
  return { page, perPage };
}

function paginate<T>(items: readonly T[], page: number, perPage: number): { pageItems: T[]; totalPages: number } {
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  return { pageItems: items.slice(start, start + perPage), totalPages };
}

function linkHeader(req: IncomingMessage, pathname: string, query: URLSearchParams, page: number, perPage: number, totalPages: number): string | null {
  if (page >= totalPages) return null;
  const base = new URLSearchParams(query);
  base.set('per_page', String(perPage));
  const next = new URLSearchParams(base);
  next.set('page', String(page + 1));
  const last = new URLSearchParams(base);
  last.set('page', String(totalPages));
  const nextUrl = absoluteUrl(req, pathname, next.toString());
  const lastUrl = absoluteUrl(req, pathname, last.toString());
  return `<${nextUrl}>; rel="next", <${lastUrl}>; rel="last"`;
}

// ---------------------------------------------------------------------------
// REST v3 shapes.
// ---------------------------------------------------------------------------

function repoJson(repo: Repo): Record<string, unknown> {
  const createdAt = isoOf(EPOCH_BASE + repo.seq);
  return {
    id: repo.id,
    node_id: globalId('Repository', [repo.id]),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER.id, node_id: globalId('User', [VIEWER.id]), type: 'User', site_admin: false },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: createdAt,
    updated_at: createdAt,
    pushed_at: createdAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    size: 0,
    open_issues_count: [...repo.issues.values()].filter((issue) => issue.state === 'open').length,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    license: null,
  };
}

function labelJson(repo: Repo, name: string): Record<string, unknown> {
  const label = repo.labels.get(name);
  return {
    id: label === undefined ? 0 : label.id,
    node_id: globalId('Label', [repo.id, name]),
    name,
    color: label?.color ?? 'ededed',
    description: '',
    default: false,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: globalId('Issue', [repo.id, issue.number]),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo, name)),
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    assignee: null,
    assignees: [],
    locked: false,
    comments: repo.comments.get(issue.number)?.length ?? 0,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}

function pullJson(repo: Repo, pull: PullRequest): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: globalId('PullRequest', [repo.id, pull.number]),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    locked: false,
    user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    head: { label: `${repo.owner}:${pull.headRef}`, ref: pull.headRef, sha: pull.headSha, user: { login: VIEWER.login, id: VIEWER.id }, repo: repoJson(repo) },
    base: { label: `${repo.owner}:${pull.baseRef}`, ref: pull.baseRef, sha: pull.baseSha, user: { login: VIEWER.login, id: VIEWER.id }, repo: repoJson(repo) },
    merged: pull.merged,
    merged_at: pull.merged ? pull.mergedAt : null,
    merge_commit_sha: pull.merged ? pull.mergeCommitSha : null,
    mergeable: pull.state === 'open' ? pullIsMergeable(repo, pull) === 'MERGEABLE' : null,
    mergeable_state: pull.state === 'open' ? (pullIsMergeable(repo, pull) === 'MERGEABLE' ? 'clean' : 'dirty') : 'unknown',
    created_at: pull.createdAt,
    updated_at: pull.createdAt,
    closed_at: pull.state === 'closed' ? pull.mergedAt : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function parseIdent(line: string): { name: string; email: string; date: string } {
  const match = /^(.*) <(.*)> (\d+) [+-]\d{4}$/.exec(line);
  if (match === null) return { name: line, email: '', date: isoOf(EPOCH_BASE) };
  return { name: match[1] as string, email: match[2] as string, date: isoOf(Number(match[3])) };
}

function commitJson(repo: Repo, sha: string): Record<string, unknown> | null {
  const object = repo.objects.get(sha);
  if (object === undefined || object.type !== 'commit') return null;
  const commit = parseCommit(object.data);
  const author = parseIdent(commit.author);
  const committer = parseIdent(commit.committer);
  const message = commit.message.endsWith('\n') ? commit.message.slice(0, -1) : commit.message;
  return {
    sha,
    node_id: globalId('Commit', [repo.id, sha]),
    commit: {
      message,
      author: { name: author.name, email: author.email, date: author.date },
      committer: { name: committer.name, email: committer.email, date: committer.date },
      tree: { sha: commit.tree },
    },
    author: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    committer: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
    parents: commit.parents.map((parent) => ({ sha: parent })),
    url: `/api/v3/repos/${repo.owner}/${repo.name}/commits/${sha}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${sha}`,
  };
}

/** Commits reachable from a tip, newest first (walk order). */
function listCommits(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'commit') continue;
    out.push(oid);
    const parents = parseCommit(object.data).parents;
    for (let i = parents.length - 1; i >= 0; i -= 1) stack.push(parents[i] as string);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Contents: one file change is one commit on a branch.
// ---------------------------------------------------------------------------

interface ContentChangeResult {
  commitSha: string;
  contentSha: string | null;
  created: boolean;
}

/**
 * Apply a contents change on `branch` (creating the branch from the default tip
 * when it does not exist yet) and commit it. `content === null` deletes the file.
 */
function applyContentChange(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer | null,
  message: string,
): ContentChangeResult {
  let tip = branchTip(repo, branch);
  if (tip === null && branch !== repo.defaultBranch) {
    const defaultTip = branchTip(repo, repo.defaultBranch);
    if (defaultTip !== null) {
      repo.refs.set(`refs/heads/${branch}`, defaultTip);
      tip = defaultTip;
    }
  }
  const files = tip === null ? new Map<string, string>() : filesAtCommit(repo, tip);
  const existed = files.has(path);
  let contentSha: string | null = null;
  if (content === null) {
    files.delete(path);
  } else {
    contentSha = storeBlob(repo, content);
    files.set(path, contentSha);
  }
  const parents = tip === null ? [] : [tip];
  const commitSha = createFileCommit(repo, files, parents, message);
  repo.refs.set(`refs/heads/${branch}`, commitSha);
  return { commitSha, contentSha, created: !existed };
}

/** Resolve a contents ref (branch name, sha, or empty) to a commit oid. */
function contentsTip(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') return branchTip(repo, repo.defaultBranch);
  return resolveRefToCommit(repo, ref);
}

function treeEntryAt(repo: Repo, treeOid: string, segments: readonly string[]): { oid: string; mode: string } | null {
  let current = treeOid;
  for (const segment of segments) {
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((candidate) => candidate.name === segment);
    if (entry === undefined) return null;
    current = entry.oid;
  }
  const parent = segments.slice(0, -1);
  void parent;
  const object = repo.objects.get(current);
  if (object === undefined) return null;
  // Re-derive the mode from the parent tree.
  let mode = object.type === 'tree' ? '40000' : '100644';
  if (segments.length > 0) {
    let walkOid = treeOid;
    for (let i = 0; i < segments.length; i += 1) {
      const walkObject = repo.objects.get(walkOid);
      if (walkObject === undefined || walkObject.type !== 'tree') return null;
      const entry = parseTree(walkObject.data).find((candidate) => candidate.name === segments[i]);
      if (entry === undefined) return null;
      if (i === segments.length - 1) mode = entry.mode;
      walkOid = entry.oid;
    }
  }
  return { oid: current, mode };
}

function directoryListing(repo: Repo, treeOid: string, dirPath: string): Record<string, unknown>[] {
  const object = repo.objects.get(treeOid);
  if (object === undefined || object.type !== 'tree') return [];
  const entries: Record<string, unknown>[] = [];
  for (const entry of parseTree(object.data)) {
    const path = dirPath === '' ? entry.name : `${dirPath}/${entry.name}`;
    if (entry.mode === '40000') {
      entries.push({ type: 'dir', name: entry.name, path, sha: entry.oid, size: 0, url: '', html_url: '' });
    } else {
      const blob = repo.objects.get(entry.oid);
      entries.push({
        type: 'file', name: entry.name, path, sha: entry.oid,
        size: blob === undefined ? 0 : blob.data.length, url: '', html_url: '', download_url: null,
      });
    }
  }
  return entries;
}

// ---------------------------------------------------------------------------
// The REST router. `segments` are the path parts after /api/v3.
// ---------------------------------------------------------------------------

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function stringField(body: JsonRecord, field: string): string {
  const value = body[field];
  return typeof value === 'string' ? value : '';
}

function handleRest(req: IncomingMessage, res: ServerResponse, segments: readonly string[], query: URLSearchParams, body: JsonRecord | null): void {
  const method = req.method ?? 'GET';
  const pathname = `/api/v3${segments.length === 0 ? '' : `/${segments.join('/')}`}`;

  // API root.
  if (segments.length === 0) {
    if (method !== 'GET') return sendError(res, 404, 'Not Found');
    return sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      current_user_authorizations_html_url: 'https://github.com/settings/applications',
      authorizations_url: '/api/v3/authorizations',
      code_search_url: '/api/v3/search/code?q={query}',
      commit_search_url: '/api/v3/search/commits?q={query}',
      emails_url: '/api/v3/user/emails',
      emojis_url: '/api/v3/emojis',
      events_url: '/api/v3/events',
      feeds_url: '/api/v3/feeds',
      followers_url: '/api/v3/user/followers',
      following_url: '/api/v3/user/following{/target}',
      gists_url: '/api/v3/gists{/gist_id}',
      hub_url: 'https://api.github.com/hub',
      issue_search_url: '/api/v3/search/issues?q={query}',
      issues_url: '/api/v3/issues',
      keys_url: '/api/v3/user/keys',
      label_search_url: '/api/v3/search/labels?q={query}',
      notifications_url: '/api/v3/notifications',
      organization_url: '/api/v3/orgs/{org}',
      organization_repositories_url: '/api/v3/orgs/{org}/repos{?type,page,per_page}',
      public_gists_url: '/api/v3/gists/public',
      rate_limit_url: '/api/v3/rate_limit',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      repository_search_url: '/api/v3/search/repositories?q={query}',
      current_user_repositories_url: '/api/v3/user/repos{?type,page,per_page}',
      user_url: '/api/v3/users/{user}',
      user_organizations_url: '/api/v3/user/orgs',
      user_repositories_url: '/api/v3/users/{user}/repos{?type,page,per_page}',
    }, { 'x-oauth-scopes': 'repo, read:org' });
  }

  if (segments[0] === 'meta' && segments.length === 1) {
    if (method !== 'GET') return sendError(res, 404, 'Not Found');
    return sendJson(res, 200, { installed_version: FORGE_VERSION, verifiable_password_authentication: true });
  }

  // The authenticated user.
  if (segments[0] === 'user' && segments.length === 1) {
    if (method !== 'GET') return sendError(res, 404, 'Not Found');
    return sendJson(res, 200, {
      login: VIEWER.login, id: VIEWER.id, node_id: globalId('User', [VIEWER.id]),
      avatar_url: '', gravatar_id: '', url: '/api/v3/user', html_url: `https://github.com/${VIEWER.login}`,
      type: 'User', site_admin: false, name: VIEWER.name, email: VIEWER.email,
      public_repos: repos.size, followers: 0, following: 0, created_at: isoOf(EPOCH_BASE), updated_at: isoOf(EPOCH_BASE),
    });
  }

  // The viewer's repositories.
  if (segments[0] === 'user' && segments[1] === 'repos' && segments.length === 2) {
    if (method === 'GET') {
      const { page, perPage } = pageParams(query);
      const all = [...repos.values()].sort((a, b) => a.seq - b.seq).map((repo) => repoJson(repo));
      const { pageItems, totalPages } = paginate(all, page, perPage);
      const link = linkHeader(req, pathname, query, page, perPage, totalPages);
      return sendJson(res, 200, pageItems, link === null ? {} : { link });
    }
    if (method === 'POST') {
      if (body === null) return sendError(res, 400, 'Invalid JSON');
      const name = stringField(body, 'name');
      if (name === '') return sendError(res, 422, 'name is required');
      if (repos.has(repoKey(VIEWER.login, name))) return sendError(res, 422, `name already exists on this account`);
      const isPrivate = body.private === true;
      const description = stringField(body, 'description');
      const defaultBranch = stringField(body, 'default_branch');
      const repo = createRepoRecord(name, isPrivate, description, defaultBranch);
      return sendJson(res, 201, repoJson(repo));
    }
    return sendError(res, 404, 'Not Found');
  }

  // Repository-scoped routes.
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1] as string;
    const name = segments[2] as string;
    const repo = findRepo(owner, name);
    const rest = segments.slice(3);
    if (repo === null) return sendError(res, 404, 'Not Found');

    if (rest.length === 0) {
      if (method === 'GET') return sendJson(res, 200, repoJson(repo));
      if (method === 'PATCH') {
        if (body === null) return sendError(res, 400, 'Invalid JSON');
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        return sendJson(res, 200, repoJson(repo));
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        return sendEmpty(res, 204);
      }
      return sendError(res, 404, 'Not Found');
    }

    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const branches: Record<string, unknown>[] = [];
        for (const [ref, oid] of [...repo.refs.entries()].sort()) {
          if (!ref.startsWith('refs/heads/')) continue;
          branches.push({ name: ref.slice('refs/heads/'.length), commit: { sha: oid }, protected: false });
        }
        return sendJson(res, 200, branches);
      }
      if (rest.length === 2 && method === 'GET') {
        const branch = rest[1] as string;
        const tip = branchTip(repo, branch);
        if (tip === null) return sendError(res, 404, 'Branch not found');
        return sendJson(res, 200, { name: branch, commit: { sha: tip, url: '' }, protected: false });
      }
      return sendError(res, 404, 'Not Found');
    }

    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const ref = query.get('sha') ?? repo.defaultBranch;
      const tip = resolveRefToCommit(repo, ref);
      if (tip === null) return sendError(res, 404, 'Not Found');
      const { page, perPage } = pageParams(query);
      const all = listCommits(repo, tip).map((sha) => commitJson(repo, sha)).filter((entry): entry is Record<string, unknown> => entry !== null);
      const { pageItems, totalPages } = paginate(all, page, perPage);
      const link = linkHeader(req, pathname, query, page, perPage, totalPages);
      return sendJson(res, 200, pageItems, link === null ? {} : { link });
    }

    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        if (body === null) return sendError(res, 400, 'Invalid JSON');
        const ref = stringField(body, 'ref');
        const sha = stringField(body, 'sha');
        if (!ref.startsWith('refs/') || !isOid(sha)) return sendError(res, 422, 'Invalid ref or sha');
        if (repo.refs.has(ref)) return sendError(res, 422, 'Reference already exists');
        if (!repo.objects.has(sha)) return sendError(res, 422, 'Object does not exist');
        repo.refs.set(ref, sha);
        return sendJson(res, 201, { ref, object: { sha, type: repo.objects.get(sha)?.type ?? 'commit' }, url: '' });
      }
      if (method === 'GET' && rest.length === 2) {
        const all: Record<string, unknown>[] = [];
        for (const [ref, oid] of [...repo.refs.entries()].sort()) {
          all.push({ ref, object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit' }, url: '' });
        }
        return sendJson(res, 200, all);
      }
      if (method === 'GET' && rest.length > 2) {
        const ref = `refs/${rest.slice(2).join('/')}`;
        const oid = repo.refs.get(ref);
        if (oid === undefined) return sendError(res, 404, 'Not Found');
        return sendJson(res, 200, { ref, object: { sha: oid, type: repo.objects.get(oid)?.type ?? 'commit' }, url: '' });
      }
      return sendError(res, 404, 'Not Found');
    }

    if (rest[0] === 'contents') {
      const contentPath = rest.slice(1).join('/');
      if (method === 'GET') {
        const ref = query.get('ref');
        const tip = contentsTip(repo, ref);
        if (tip === null) return sendError(res, 404, 'Not Found');
        const commit = repo.objects.get(tip);
        if (commit === undefined || commit.type !== 'commit') return sendError(res, 404, 'Not Found');
        const rootTree = parseCommit(commit.data).tree;
        if (contentPath === '') return sendJson(res, 200, directoryListing(repo, rootTree, ''));
        const segments = contentPath.split('/').filter((segment) => segment !== '');
        const found = treeEntryAt(repo, rootTree, segments);
        if (found === null) return sendError(res, 404, 'Not Found');
        if (found.mode === '40000') return sendJson(res, 200, directoryListing(repo, found.oid, contentPath));
        const blob = repo.objects.get(found.oid);
        if (blob === undefined) return sendError(res, 404, 'Not Found');
        return sendJson(res, 200, {
          type: 'file', encoding: 'base64', size: blob.data.length,
          name: segments[segments.length - 1] as string, path: contentPath, sha: found.oid,
          content: b64encode(blob.data), url: '', html_url: '', download_url: null,
        });
      }
      if (method === 'PUT') {
        if (body === null) return sendError(res, 400, 'Invalid JSON');
        const contentText = body.content;
        if (typeof contentText !== 'string') return sendError(res, 400, 'content is required');
        const content = b64decode(contentText);
        if (content === null) return sendError(res, 400, 'content is not valid base64');
        const message = stringField(body, 'message') || 'Update file';
        const branch = stringField(body, 'branch') || repo.defaultBranch;
        const sha = stringField(body, 'sha');
        if (sha !== '') {
          const tip = branchTip(repo, branch);
          if (tip !== null) {
            const files = filesAtCommit(repo, tip);
            const current = files.get(contentPath);
            if (current !== undefined && current !== sha) return sendError(res, 409, 'sha does not match the current file');
          }
        }
        const result = applyContentChange(repo, branch, contentPath, content, message);
        return sendJson(res, result.created ? 201 : 200, {
          content: {
            name: contentPath.split('/').pop() ?? contentPath, path: contentPath,
            sha: result.contentSha, size: content.length, type: 'file', encoding: 'base64',
          },
          commit: { sha: result.commitSha, message },
        });
      }
      if (method === 'DELETE') {
        if (body === null) return sendError(res, 400, 'Invalid JSON');
        const message = stringField(body, 'message') || 'Delete file';
        const branch = stringField(body, 'branch') || repo.defaultBranch;
        const tip = branchTip(repo, branch);
        if (tip === null) return sendError(res, 404, 'Not Found');
        const files = filesAtCommit(repo, tip);
        if (!files.has(contentPath)) return sendError(res, 404, 'Not Found');
        const result = applyContentChange(repo, branch, contentPath, null, message);
        return sendJson(res, 200, { commit: { sha: result.commitSha, message } });
      }
      return sendError(res, 404, 'Not Found');
    }

    if (rest[0] === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        return sendJson(res, 200, [...repo.labels.keys()].map((labelName) => labelJson(repo, labelName)));
      }
      if (method === 'POST' && rest.length === 1) {
        if (body === null) return sendError(res, 400, 'Invalid JSON');
        const labelName = stringField(body, 'name');
        if (labelName === '') return sendError(res, 422, 'name is required');
        const color = stringField(body, 'color') || 'ededed';
        if (!repo.labels.has(labelName)) {
          const labelId = nextGlobalLabelId;
          nextGlobalLabelId += 1;
          repo.labels.set(labelName, { name: labelName, color, id: labelId });
        }
        return sendJson(res, 201, labelJson(repo, labelName));
      }
      return sendError(res, 404, 'Not Found');
    }

    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const sort = query.get('sort') ?? 'created';
          const direction = query.get('direction') ?? 'desc';
          void sort;
          let list = [...repo.issues.values()];
          if (state === 'open') list = list.filter((issue) => issue.state === 'open');
          else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          const { page, perPage } = pageParams(query);
          const { pageItems, totalPages } = paginate(list.map((issue) => issueJson(repo, issue)), page, perPage);
          const link = linkHeader(req, pathname, query, page, perPage, totalPages);
          return sendJson(res, 200, pageItems, link === null ? {} : { link });
        }
        if (method === 'POST') {
          if (body === null) return sendError(res, 400, 'Invalid JSON');
          const title = stringField(body, 'title');
          if (title === '') return sendError(res, 422, 'title is required');
          const rawLabels = Array.isArray(body.labels) ? body.labels : [];
          const labelNames: string[] = [];
          for (const raw of rawLabels) {
            const labelName = typeof raw === 'string' ? raw : isRecord(raw) ? stringField(raw, 'name') : '';
            if (labelName === '') continue;
            if (!repo.labels.has(labelName)) return sendError(res, 422, `Label '${labelName}' does not exist`);
            labelNames.push(labelName);
          }
          const number = repo.nextIssue;
          repo.nextIssue += 1;
          const ts = nextTimestamp();
          const issue: Issue = {
            id: nextIssueDbId, number, title, body: stringField(body, 'body'),
            state: 'open', labels: labelNames, seq: ts,
            createdAt: isoOf(ts), updatedAt: isoOf(ts),
          };
          nextIssueDbId += 1;
          repo.issues.set(number, issue);
          return sendJson(res, 201, issueJson(repo, issue));
        }
        return sendError(res, 404, 'Not Found');
      }
      const issueNumber = Number(rest[1]);
      if (!Number.isInteger(issueNumber) || issueNumber < 1) return sendError(res, 404, 'Not Found');
      const issue = repo.issues.get(issueNumber);
      if (rest.length === 2) {
        if (issue === undefined) return sendError(res, 404, 'Not Found');
        if (method === 'GET') return sendJson(res, 200, issueJson(repo, issue));
        if (method === 'PATCH') {
          if (body === null) return sendError(res, 400, 'Invalid JSON');
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          issue.updatedAt = isoOf(nextTimestamp());
          return sendJson(res, 200, issueJson(repo, issue));
        }
        return sendError(res, 404, 'Not Found');
      }
      if (rest[2] === 'comments') {
        if (issue === undefined) return sendError(res, 404, 'Not Found');
        if (method === 'GET') {
          const comments = repo.comments.get(issueNumber) ?? [];
          return sendJson(res, 200, comments.map((comment) => ({
            id: comment.id, node_id: globalId('IssueComment', [repo.id, issueNumber, comment.id]),
            body: comment.body, user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
            created_at: comment.createdAt, updated_at: comment.createdAt,
            html_url: '', url: '',
          })));
        }
        if (method === 'POST') {
          if (body === null) return sendError(res, 400, 'Invalid JSON');
          const commentBody = stringField(body, 'body');
          if (commentBody === '') return sendError(res, 422, 'body is required');
          const comment: Comment = { id: nextGlobalCommentId, body: commentBody, createdAt: isoOf(nextTimestamp()) };
          nextGlobalCommentId += 1;
          const list = repo.comments.get(issueNumber) ?? [];
          list.push(comment);
          repo.comments.set(issueNumber, list);
          return sendJson(res, 201, {
            id: comment.id, node_id: globalId('IssueComment', [repo.id, issueNumber, comment.id]),
            body: comment.body, user: { login: VIEWER.login, id: VIEWER.id, type: 'User' },
            created_at: comment.createdAt, updated_at: comment.createdAt, html_url: '', url: '',
          });
        }
        return sendError(res, 404, 'Not Found');
      }
      return sendError(res, 404, 'Not Found');
    }

    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state === 'open') list = list.filter((pull) => pull.state === 'open');
          else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
          list.sort((a, b) => b.seq - a.seq);
          const { page, perPage } = pageParams(query);
          const { pageItems, totalPages } = paginate(list.map((pull) => pullJson(repo, pull)), page, perPage);
          const link = linkHeader(req, pathname, query, page, perPage, totalPages);
          return sendJson(res, 200, pageItems, link === null ? {} : { link });
        }
        if (method === 'POST') {
          if (body === null) return sendError(res, 400, 'Invalid JSON');
          const title = stringField(body, 'title');
          let head = stringField(body, 'head');
          let base = stringField(body, 'base');
          if (title === '' || head === '' || base === '') return sendError(res, 422, 'title, head and base are required');
          if (head.includes(':')) head = head.split(':').slice(1).join(':');
          if (base.includes(':')) base = base.split(':').slice(1).join(':');
          const headSha = branchTip(repo, head);
          const baseSha = branchTip(repo, base);
          if (headSha === null || baseSha === null) return sendError(res, 422, 'head or base branch does not exist');
          for (const existing of repo.pulls.values()) {
            if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
              return sendError(res, 422, 'A pull request already exists for this head branch');
            }
          }
          const number = repo.nextPull;
          repo.nextPull += 1;
          const ts = nextTimestamp();
          const pull: PullRequest = {
            id: nextPullDbId, number, title, body: stringField(body, 'body'), state: 'open',
            headRef: head, baseRef: base, headSha, baseSha,
            merged: false, mergedAt: '', mergeCommitSha: '', seq: ts, createdAt: isoOf(ts),
          };
          nextPullDbId += 1;
          repo.pulls.set(number, pull);
          return sendJson(res, 201, pullJson(repo, pull));
        }
        return sendError(res, 404, 'Not Found');
      }
      const pullNumber = Number(rest[1]);
      if (!Number.isInteger(pullNumber) || pullNumber < 1) return sendError(res, 404, 'Not Found');
      const pull = repo.pulls.get(pullNumber);
      if (rest.length === 2) {
        if (pull === undefined) return sendError(res, 404, 'Not Found');
        if (method === 'GET') return sendJson(res, 200, pullJson(repo, pull));
        return sendError(res, 404, 'Not Found');
      }
      if (rest[2] === 'files' && method === 'GET') {
        if (pull === undefined) return sendError(res, 404, 'Not Found');
        const baseFiles = filesAtCommit(repo, pull.baseSha);
        const headFiles = filesAtCommit(repo, pull.headSha);
        const changes = diffFileMaps(repo, baseFiles, headFiles);
        return sendJson(res, 200, changes.map((change) => ({
          filename: change.path,
          status: change.status === 'removed' ? 'removed' : change.status,
          additions: change.additions,
          deletions: change.deletions,
          changes: change.additions + change.deletions,
          blob_url: '', raw_url: '', contents_url: '',
        })));
      }
      if (rest[2] === 'merge' && method === 'PUT') {
        if (pull === undefined) return sendError(res, 404, 'Not Found');
        if (pull.state !== 'open') return sendError(res, 405, 'Pull request is not open');
        const baseTip = branchTip(repo, pull.baseRef);
        const headTip = branchTip(repo, pull.headRef);
        if (baseTip === null || headTip === null) return sendError(res, 405, 'Head or base branch is missing');
        const merged = squashMergeFiles(repo, baseTip, headTip);
        if (merged.conflict) return sendError(res, 405, 'Merge conflict');
        const mergeMessage = `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}`;
        const mergeSha = createFileCommit(repo, merged.files, [baseTip], mergeMessage);
        repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
        pull.state = 'closed';
        pull.merged = true;
        pull.mergedAt = isoOf(nextTimestamp());
        pull.mergeCommitSha = mergeSha;
        return sendJson(res, 200, { merged: true, sha: mergeSha, message: mergeMessage });
      }
      return sendError(res, 404, 'Not Found');
    }

    return sendError(res, 404, 'Not Found');
  }

  return sendError(res, 404, 'Not Found');
}

// ---------------------------------------------------------------------------
// GraphQL v4: a small parser and executor for the documents gh sends.
// ---------------------------------------------------------------------------

type GqlToken =
  | { kind: 'name'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: string }
  | { kind: 'punct'; value: string };

function lexGraphQL(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < source.length && source[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let value = '';
      i += 1;
      while (i < source.length && source[i] !== '"') {
        if (source[i] === '\\' && i + 1 < source.length) {
          const escaped = source[i + 1] as string;
          if (escaped === 'n') value += '\n';
          else if (escaped === 't') value += '\t';
          else if (escaped === 'r') value += '\r';
          else value += escaped;
          i += 2;
        } else {
          value += source[i] as string;
          i += 1;
        }
      }
      i += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let value = '';
      while (i < source.length && /[0-9.]/.test(source[i] as string)) {
        value += source[i] as string;
        i += 1;
      }
      tokens.push({ kind: 'int', value });
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let value = '';
      while (i < source.length && /[A-Za-z0-9_]/.test(source[i] as string)) {
        value += source[i] as string;
        i += 1;
      }
      tokens.push({ kind: 'name', value });
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return tokens;
}

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: { name: string; value: GqlValue }[] };

interface GqlField {
  alias: string | null;
  name: string;
  args: { name: string; value: GqlValue }[];
  selections: GqlSelection[];
}
type GqlSelection =
  | { kind: 'field'; field: GqlField }
  | { kind: 'inline'; typeName: string | null; selections: GqlSelection[] }
  | { kind: 'spread'; name: string };

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: { name: string; defaultValue: GqlValue | null }[];
  selections: GqlSelection[];
}

class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;
  fragments = new Map<string, GqlSelection[]>();

  constructor(source: string) {
    this.tokens = lexGraphQL(source);
  }

  private peek(): GqlToken | null {
    return this.tokens[this.pos] ?? null;
  }
  private next(): GqlToken {
    const token = this.tokens[this.pos];
    if (token === undefined) throw new Error('unexpected end of GraphQL document');
    this.pos += 1;
    return token;
  }
  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected ${value} in GraphQL document`);
  }
  private skipDirectives(): void {
    while (this.peek()?.kind === 'punct' && this.peek()?.value === '@') {
      this.next();
      const name = this.next();
      if (name.kind !== 'name') throw new Error('expected directive name');
      if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') this.parseArgs();
    }
  }

  parseDocument(): GqlOperation[] {
    const operations: GqlOperation[] = [];
    while (this.peek() !== null) {
      const token = this.peek() as GqlToken;
      if (token.kind === 'name' && token.value === 'fragment') {
        this.next();
        const nameToken = this.next();
        if (nameToken.kind !== 'name') throw new Error('expected fragment name');
        const onToken = this.next();
        if (onToken.kind !== 'name' || onToken.value !== 'on') throw new Error('expected "on" in fragment');
        const typeToken = this.next();
        if (typeToken.kind !== 'name') throw new Error('expected fragment type');
        this.skipDirectives();
        this.fragments.set(nameToken.value, this.parseSelectionSet());
        continue;
      }
      operations.push(this.parseOperation());
    }
    return operations;
  }

  private parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    let name: string | null = null;
    const first = this.peek();
    if (first?.kind === 'name' && (first.value === 'query' || first.value === 'mutation')) {
      kind = this.next().value as 'query' | 'mutation';
      const maybeName = this.peek();
      if (maybeName?.kind === 'name') {
        name = this.next().value;
      }
    }
    const variables: { name: string; defaultValue: GqlValue | null }[] = [];
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '(') {
      this.next();
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ')')) {
        const dollar = this.next();
        if (dollar.kind !== 'punct' || dollar.value !== '$') throw new Error('expected $ in variable definition');
        const varName = this.next();
        if (varName.kind !== 'name') throw new Error('expected variable name');
        this.expectPunct(':');
        this.parseType();
        let defaultValue: GqlValue | null = null;
        if (this.peek()?.kind === 'punct' && this.peek()?.value === '=') {
          this.next();
          defaultValue = this.parseValue();
        }
        variables.push({ name: varName.value, defaultValue });
      }
      this.expectPunct(')');
    }
    this.skipDirectives();
    const selections = this.parseSelectionSet();
    return { kind, name, variables, selections };
  }

  private parseType(): void {
    const token = this.peek();
    if (token?.kind === 'punct' && token.value === '[') {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else if (token?.kind === 'name') {
      this.next();
    } else {
      throw new Error('expected a GraphQL type');
    }
    if (this.peek()?.kind === 'punct' && this.peek()?.value === '!') this.next();
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    const token = this.peek();
    if (token?.kind === 'punct' && token.value === '...') {
      this.next();
      const nextToken = this.peek();
      if (nextToken?.kind === 'name' && nextToken.value === 'on') {
        this.next();
        const typeToken = this.next();
        if (typeToken.kind !== 'name') throw new Error('expected type in inline fragment');
        this.skipDirectives();
        return { kind: 'inline', typeName: typeToken.value, selections: this.parseSelectionSet() };
      }
      if (nextToken?.kind === 'name') {
        this.next();
        this.skipDirectives();
        return { kind: 'spread', name: nextToken.value };
      }
      this.skipDirectives();
      return { kind: 'inline', typeName: null, selections: this.parseSelectionSet() };
    }
    if (token?.kind !== 'name') throw new Error('expected a field name in GraphQL document');
    const first = this.next();
    let alias: string | null = null;
    let name = first.value;
    if (this.peek()?.kind === 'punct' && this.peek()?.value === ':') {
      this.next();
      alias = name;
      const nameToken = this.next();
      if (nameToken.kind !== 'name') throw new Error('expected a field name after alias');
      name = nameToken.value;
    }
    const args = this.peek()?.kind === 'punct' && this.peek()?.value === '(' ? this.parseArgs() : [];
    this.skipDirectives();
    const selections = this.peek()?.kind === 'punct' && this.peek()?.value === '{' ? this.parseSelectionSet() : [];
    return { kind: 'field', field: { alias, name, args, selections } };
  }

  private parseArgs(): { name: string; value: GqlValue }[] {
    this.expectPunct('(');
    const args: { name: string; value: GqlValue }[] = [];
    while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ')')) {
      const nameToken = this.next();
      if (nameToken.kind !== 'name') throw new Error('expected argument name');
      this.expectPunct(':');
      args.push({ name: nameToken.value, value: this.parseValue() });
    }
    this.expectPunct(')');
    return args;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'int') return { kind: 'int', value: Number(token.value) };
    if (token.kind === 'punct' && token.value === '$') {
      const nameToken = this.next();
      if (nameToken.kind !== 'name') throw new Error('expected variable name');
      return { kind: 'variable', name: nameToken.value };
    }
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === ']')) items.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields: { name: string; value: GqlValue }[] = [];
      while (!(this.peek()?.kind === 'punct' && this.peek()?.value === '}')) {
        const nameToken = this.next();
        if (nameToken.kind !== 'name') throw new Error('expected object field name');
        this.expectPunct(':');
        fields.push({ name: nameToken.value, value: this.parseValue() });
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error('unexpected value in GraphQL document');
  }
}

/** Resolve a parsed value against the operation's variables. */
function resolveValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'variable':
      return variables[value.name] ?? null;
    case 'string':
      return value.value;
    case 'int':
      return value.value;
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'list':
      return value.items.map((item) => resolveValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const field of value.fields) out[field.name] = resolveValue(field.value, variables);
      return out;
    }
  }
}

function argsMap(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const arg of field.args) out[arg.name] = resolveValue(arg.value, variables);
  return out;
}

// The executor's value wrappers: every object carries its GraphQL type.
type GqlObject =
  | { __type: 'User'; login: string; id: number }
  | { __type: 'Repository'; repo: Repo }
  | { __type: 'Issue'; repo: Repo; issue: Issue }
  | { __type: 'PullRequest'; repo: Repo; pull: PullRequest }
  | { __type: 'IssueConnection'; repo: Repo; issues: Issue[]; endCursor: string | null; hasNextPage: boolean }
  | { __type: 'PullRequestConnection'; repo: Repo; pulls: PullRequest[] }
  | { __type: 'PullRequestFileConnection'; repo: Repo; pull: PullRequest; first: number }
  | { __type: 'TypeInfo'; name: string; fields: string[]; enumValues: string[] }
  | { __type: 'Ref'; name: string }
  | { __type: 'PageInfo'; hasNextPage: boolean; endCursor: string | null }
  | { __type: 'CommentEdge'; repo: Repo; issue: Issue; comment: Comment };

const ISSUE_TYPE_FIELDS = [
  'id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'author', 'labels', 'comments', 'closedAt',
  'databaseId', 'titleHTML', 'bodyHTML', 'isPinned', 'locked', 'milestone', 'assignees', 'participants',
];
const PULL_REQUEST_TYPE_FIELDS = [
  'id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files',
  'title', 'body', 'url', 'createdAt', 'author', 'headRefOid', 'baseRefOid', 'mergeCommit',
  'mergedAt', 'mergeCommitSha', 'databaseId', 'isDraft', 'labels', 'reviews', 'commits',
];
const REPOSITORY_TYPE_FIELDS = [
  'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission',
  'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'isPrivate',
  'url', 'createdAt', 'updatedAt', 'stargazerCount', 'forkCount', 'licenseInfo', 'languages',
  'defaultBranch', 'homepageUrl', 'visibility', 'isArchived', 'hasWikiEnabled', 'hasProjectsEnabled',
];

function typeInfoFor(name: string): { fields: string[]; enumValues: string[] } {
  switch (name) {
    case 'Issue':
      return { fields: ISSUE_TYPE_FIELDS, enumValues: [] };
    case 'PullRequest':
      return { fields: PULL_REQUEST_TYPE_FIELDS, enumValues: [] };
    case 'Repository':
      return { fields: REPOSITORY_TYPE_FIELDS, enumValues: [] };
    case 'SearchType':
      return { fields: [], enumValues: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT'] };
    case 'User':
      return { fields: ['id', 'login', 'name', 'email', 'url', 'avatarUrl', 'createdAt'], enumValues: [] };
    default:
      return { fields: [], enumValues: [] };
  }
}

function issueStateGql(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}
function pullStateGql(state: 'open' | 'closed'): string {
  return state === 'open' ? 'OPEN' : 'CLOSED';
}

function cursorFor(number: number): string {
  return Buffer.from(`cursor:${number}`, 'utf8').toString('base64url');
}
function numberAfterCursor(cursor: string | null | undefined): number | null {
  if (typeof cursor !== 'string' || cursor === '') return null;
  try {
    const text = Buffer.from(cursor, 'base64url').toString('utf8');
    const match = /^cursor:(\d+)$/.exec(text);
    return match === null ? null : Number(match[1]);
  } catch {
    return null;
  }
}

function findRepoById(databaseId: number): Repo | null {
  for (const repo of repos.values()) if (repo.id === databaseId) return repo;
  return null;
}

function findIssueByGlobalId(id: string): { repo: Repo; issue: Issue } | null {
  const parsed = parseGlobalId(id);
  if (parsed === null || parsed.kind !== 'Issue' || parsed.parts.length < 2) return null;
  const repo = findRepoById(Number(parsed.parts[0]));
  if (repo === null) return null;
  const issue = repo.issues.get(Number(parsed.parts[1]));
  return issue === undefined ? null : { repo, issue };
}

function findPullByGlobalId(id: string): { repo: Repo; pull: PullRequest } | null {
  const parsed = parseGlobalId(id);
  if (parsed === null || parsed.kind !== 'PullRequest' || parsed.parts.length < 2) return null;
  const repo = findRepoById(Number(parsed.parts[0]));
  if (repo === null) return null;
  const pull = repo.pulls.get(Number(parsed.parts[1]));
  return pull === undefined ? null : { repo, pull };
}

function createIssueRecord(repo: Repo, title: string, body: string): Issue {
  const number = repo.nextIssue;
  repo.nextIssue += 1;
  const ts = nextTimestamp();
  const issue: Issue = {
    id: nextIssueDbId, number, title, body, state: 'open', labels: [],
    seq: ts, createdAt: isoOf(ts), updatedAt: isoOf(ts),
  };
  nextIssueDbId += 1;
  repo.issues.set(number, issue);
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, head: string, base: string): PullRequest | null {
  const headSha = branchTip(repo, head);
  const baseSha = branchTip(repo, base);
  if (headSha === null || baseSha === null) return null;
  for (const existing of repo.pulls.values()) {
    if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) return null;
  }
  const number = repo.nextPull;
  repo.nextPull += 1;
  const ts = nextTimestamp();
  const pull: PullRequest = {
    id: nextPullDbId, number, title, body, state: 'open',
    headRef: head, baseRef: base, headSha, baseSha,
    merged: false, mergedAt: '', mergeCommitSha: '', seq: ts, createdAt: isoOf(ts),
  };
  nextPullDbId += 1;
  repo.pulls.set(number, pull);
  return pull;
}

function mergePullRecord(repo: Repo, pull: PullRequest): { ok: boolean; reason?: string } {
  if (pull.state !== 'open') return { ok: false, reason: 'Pull request is not open' };
  const baseTip = branchTip(repo, pull.baseRef);
  const headTip = branchTip(repo, pull.headRef);
  if (baseTip === null || headTip === null) return { ok: false, reason: 'Head or base branch is missing' };
  const merged = squashMergeFiles(repo, baseTip, headTip);
  if (merged.conflict) return { ok: false, reason: 'Merge conflict' };
  const mergeMessage = `Merge pull request #${pull.number} from ${repo.owner}/${pull.headRef}`;
  const mergeSha = createFileCommit(repo, merged.files, [baseTip], mergeMessage);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeSha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoOf(nextTimestamp());
  pull.mergeCommitSha = mergeSha;
  return { ok: true };
}

interface GqlError {
  message: string;
}

class GqlExecutor {
  private errors: GqlError[] = [];
  private fragments: Map<string, GqlSelection[]>;

  constructor(fragments: Map<string, GqlSelection[]>) {
    this.fragments = fragments;
  }

  execute(operation: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown>; errors: GqlError[] } {
    this.errors = [];
    const vars: Record<string, unknown> = { ...variables };
    for (const definition of operation.variables) {
      if (!(definition.name in vars) && definition.defaultValue !== null) {
        vars[definition.name] = resolveValue(definition.defaultValue, vars);
      }
    }
    const data: Record<string, unknown> = {};
    if (operation.kind === 'query') {
      this.executeSelections('Query', null, operation.selections, vars, data);
    } else {
      this.executeSelections('Mutation', null, operation.selections, vars, data);
    }
    return { data, errors: this.errors };
  }

  private executeSelections(
    typeName: string,
    value: GqlObject | null,
    selections: readonly GqlSelection[],
    variables: Record<string, unknown>,
    out: Record<string, unknown>,
  ): void {
    for (const selection of selections) {
      if (selection.kind === 'field') {
        const field = selection.field;
        const key = field.alias ?? field.name;
        out[key] = this.resolveField(typeName, value, field, variables);
      } else if (selection.kind === 'inline') {
        if (selection.typeName === null || selection.typeName === typeName) {
          this.executeSelections(typeName, value, selection.selections, variables, out);
        }
      } else if (selection.kind === 'spread') {
        const fragment = this.fragments.get(selection.name);
        if (fragment !== undefined) this.executeSelections(typeName, value, fragment, variables, out);
      }
    }
  }

  private resolveField(
    typeName: string,
    value: GqlObject | null,
    field: GqlField,
    variables: Record<string, unknown>,
  ): unknown {
    const args = argsMap(field, variables);
    const selections = field.selections;
    const sub = (nextType: string, nextValue: GqlObject | null): Record<string, unknown> | null => {
      if (nextValue === null) return null;
      const out: Record<string, unknown> = {};
      this.executeSelections(nextType, nextValue, selections, variables, out);
      return out;
    };
    const unknownField = (): null => {
      this.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
      return null;
    };

    if (typeName === 'Query') {
      if (field.name === 'viewer') {
        return sub('User', { __type: 'User', login: VIEWER.login, id: VIEWER.id });
      }
      if (field.name === 'repository') {
        const owner = args.owner as string | undefined;
        const name = args.name as string | undefined;
        if (owner !== VIEWER.login || typeof name !== 'string') return null;
        const repo = findRepo(owner, name);
        return repo === null ? null : sub('Repository', { __type: 'Repository', repo });
      }
      if (field.name === 'node') {
        const id = args.id as string | undefined;
        if (typeof id !== 'string') return null;
        const parsed = parseGlobalId(id);
        if (parsed === null) return null;
        if (parsed.kind === 'Repository') {
          const repo = findRepoById(Number(parsed.parts[0]));
          return repo === null ? null : sub('Repository', { __type: 'Repository', repo });
        }
        if (parsed.kind === 'Issue') {
          const found = findIssueByGlobalId(id);
          return found === null ? null : sub('Issue', { __type: 'Issue', repo: found.repo, issue: found.issue });
        }
        if (parsed.kind === 'PullRequest') {
          const found = findPullByGlobalId(id);
          return found === null ? null : sub('PullRequest', { __type: 'PullRequest', repo: found.repo, pull: found.pull });
        }
        return null;
      }
      if (field.name === '__type') {
        const name = args.name as string | undefined;
        if (typeof name !== 'string') return null;
        const info = typeInfoFor(name);
        return sub('TypeInfo', { __type: 'TypeInfo', name, fields: info.fields, enumValues: info.enumValues });
      }
      return unknownField();
    }

    if (typeName === 'Mutation') {
      if (field.name === 'createIssue') {
        const input = args.input as Record<string, unknown> | undefined;
        const repositoryId = input?.repositoryId as string | undefined;
        const title = input?.title as string | undefined;
        if (typeof repositoryId !== 'string' || typeof title !== 'string') {
          this.errors.push({ message: 'createIssue needs a repositoryId and a title.' });
          return null;
        }
        const parsed = parseGlobalId(repositoryId);
        const repo = parsed !== null && parsed.kind === 'Repository' ? findRepoById(Number(parsed.parts[0])) : null;
        if (repo === null) {
          this.errors.push({ message: 'createIssue: unknown repository.' });
          return null;
        }
        const issue = createIssueRecord(repo, title, (input.body as string | undefined) ?? '');
        return this.payloadIssue(issue, repo, selections, variables);
      }
      if (field.name === 'closeIssue') {
        const input = args.input as Record<string, unknown> | undefined;
        const issueId = input?.issueId as string | undefined;
        if (typeof issueId !== 'string') {
          this.errors.push({ message: 'closeIssue needs an issueId.' });
          return null;
        }
        const found = findIssueByGlobalId(issueId);
        if (found === null) {
          this.errors.push({ message: 'closeIssue: unknown issue.' });
          return null;
        }
        found.issue.state = 'closed';
        found.issue.updatedAt = isoOf(nextTimestamp());
        return this.payloadIssue(found.issue, found.repo, selections, variables);
      }
      if (field.name === 'createPullRequest') {
        const input = args.input as Record<string, unknown> | undefined;
        const repositoryId = input?.repositoryId as string | undefined;
        const headRefName = input?.headRefName as string | undefined;
        const baseRefName = input?.baseRefName as string | undefined;
        const title = input?.title as string | undefined;
        if (typeof repositoryId !== 'string' || typeof headRefName !== 'string' || typeof baseRefName !== 'string' || typeof title !== 'string') {
          this.errors.push({ message: 'createPullRequest needs repositoryId, headRefName, baseRefName and title.' });
          return null;
        }
        const parsed = parseGlobalId(repositoryId);
        const repo = parsed !== null && parsed.kind === 'Repository' ? findRepoById(Number(parsed.parts[0])) : null;
        if (repo === null) {
          this.errors.push({ message: 'createPullRequest: unknown repository.' });
          return null;
        }
        const pull = createPullRecord(repo, title, (input.body as string | undefined) ?? '', headRefName, baseRefName);
        if (pull === null) {
          this.errors.push({ message: 'createPullRequest: the head or base branch does not exist, or a pull request is already open.' });
          return null;
        }
        return this.payloadPull(pull, repo, selections, variables);
      }
      if (field.name === 'mergePullRequest') {
        const input = args.input as Record<string, unknown> | undefined;
        const pullRequestId = input?.pullRequestId as string | undefined;
        if (typeof pullRequestId !== 'string') {
          this.errors.push({ message: 'mergePullRequest needs a pullRequestId.' });
          return null;
        }
        const found = findPullByGlobalId(pullRequestId);
        if (found === null) {
          this.errors.push({ message: 'mergePullRequest: unknown pull request.' });
          return null;
        }
        const result = mergePullRecord(found.repo, found.pull);
        if (!result.ok) {
          this.errors.push({ message: `mergePullRequest: ${result.reason ?? 'could not merge'}.` });
          return null;
        }
        return this.payloadPull(found.pull, found.repo, selections, variables);
      }
      if (field.name === 'addComment') {
        const input = args.input as Record<string, unknown> | undefined;
        const subjectId = input?.subjectId as string | undefined;
        const commentBody = input?.body as string | undefined;
        if (typeof subjectId !== 'string' || typeof commentBody !== 'string') {
          this.errors.push({ message: 'addComment needs a subjectId and a body.' });
          return null;
        }
        const found = findIssueByGlobalId(subjectId);
        if (found === null) {
          this.errors.push({ message: 'addComment: unknown subject.' });
          return null;
        }
        const comment: Comment = { id: nextGlobalCommentId, body: commentBody, createdAt: isoOf(nextTimestamp()) };
        nextGlobalCommentId += 1;
        const list = found.repo.comments.get(found.issue.number) ?? [];
        list.push(comment);
        found.repo.comments.set(found.issue.number, list);
        const out: Record<string, unknown> = {};
        for (const selection of selections) {
          if (selection.kind === 'field' && selection.field.name === 'commentEdge') {
            const edgeOut: Record<string, unknown> = {};
            this.executeSelections('CommentEdge', { __type: 'CommentEdge', repo: found.repo, issue: found.issue, comment }, selection.field.selections, variables, edgeOut);
            out.commentEdge = edgeOut;
          }
        }
        return out;
      }
      return unknownField();
    }

    if (value === null) return null;

    if (typeName === 'User') {
      const user = value as { __type: 'User'; login: string; id: number };
      if (field.name === 'login') return user.login;
      if (field.name === 'id') return globalId('User', [user.id]);
      if (field.name === 'name') return VIEWER.name;
      if (field.name === 'email') return VIEWER.email;
      if (field.name === 'url') return `https://github.com/${user.login}`;
      return unknownField();
    }

    if (typeName === 'Repository') {
      const repo = (value as { __type: 'Repository'; repo: Repo }).repo;
      switch (field.name) {
        case 'id':
          return globalId('Repository', [repo.id]);
        case 'databaseId':
          return repo.id;
        case 'name':
          return repo.name;
        case 'nameWithOwner':
          return `${repo.owner}/${repo.name}`;
        case 'owner':
          return sub('User', { __type: 'User', login: repo.owner, id: VIEWER.id });
        case 'defaultBranchRef': {
          const tip = branchTip(repo, repo.defaultBranch);
          if (tip === null) return null;
          return sub('Ref', { __type: 'Ref', name: repo.defaultBranch });
        }
        case 'viewerPermission':
          return 'ADMIN';
        case 'hasIssuesEnabled':
          return true;
        case 'description':
          return repo.description;
        case 'isPrivate':
          return repo.isPrivate;
        case 'url':
          return `https://github.com/${repo.owner}/${repo.name}`;
        case 'issue': {
          const number = args.number as number | undefined;
          if (typeof number !== 'number') return null;
          const issue = repo.issues.get(number);
          return issue === undefined ? null : sub('Issue', { __type: 'Issue', repo, issue });
        }
        case 'issues': {
          const first = typeof args.first === 'number' ? args.first : 100;
          const after = numberAfterCursor(args.after as string | null | undefined);
          const states = Array.isArray(args.states) ? (args.states as string[]) : null;
          const orderBy = isRecord(args.orderBy) ? (args.orderBy as Record<string, unknown>) : null;
          let list = [...repo.issues.values()];
          if (states !== null) {
            const wanted = new Set(states.map((state) => String(state).toLowerCase()));
            list = list.filter((issue) => wanted.has(issue.state));
          }
          const direction = orderBy?.direction === 'DESC' ? 'desc' : orderBy?.direction === 'ASC' ? 'asc' : 'asc';
          list.sort((a, b) => (direction === 'desc' ? b.seq - a.seq : a.seq - b.seq));
          if (after !== null) list = list.filter((issue) => issue.number > after);
          const page = list.slice(0, first);
          const hasNextPage = list.length > first;
          const endCursor = page.length > 0 ? cursorFor((page[page.length - 1] as Issue).number) : null;
          return sub('IssueConnection', { __type: 'IssueConnection', repo, issues: page, endCursor, hasNextPage });
        }
        case 'pullRequest': {
          const number = args.number as number | undefined;
          if (typeof number !== 'number') return null;
          const pull = repo.pulls.get(number);
          return pull === undefined ? null : sub('PullRequest', { __type: 'PullRequest', repo, pull });
        }
        case 'pullRequests': {
          const first = typeof args.first === 'number' ? args.first : 100;
          const states = Array.isArray(args.states) ? (args.states as string[]) : null;
          let list = [...repo.pulls.values()];
          if (states !== null) {
            const wanted = new Set(states.map((state) => String(state).toLowerCase()));
            list = list.filter((pull) => wanted.has(pull.state));
          } else {
            list = list.filter((pull) => pull.state === 'open');
          }
          list.sort((a, b) => b.seq - a.seq);
          const page = list.slice(0, first);
          return sub('PullRequestConnection', { __type: 'PullRequestConnection', repo, pulls: page });
        }
        default:
          return unknownField();
      }
    }

    if (typeName === 'Issue') {
      const issue = (value as { __type: 'Issue'; issue: Issue }).issue;
      const repo = (value as { __type: 'Issue'; repo: Repo }).repo;
      switch (field.name) {
        case 'id':
          return globalId('Issue', [repo.id, issue.number]);
        case 'databaseId':
          return issue.id;
        case 'number':
          return issue.number;
        case 'title':
          return issue.title;
        case 'body':
          return issue.body;
        case 'state':
          return issueStateGql(issue.state);
        case 'url':
          return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
        case 'createdAt':
          return issue.createdAt;
        case 'author':
          return sub('User', { __type: 'User', login: VIEWER.login, id: VIEWER.id });
        case 'labels':
          return { nodes: issue.labels.map((name) => ({ name })) };
        case 'comments':
          return { nodes: (repo.comments.get(issue.number) ?? []).map((comment) => ({ id: globalId('IssueComment', [repo.id, issue.number, comment.id]), body: comment.body })) };
        default:
          return unknownField();
      }
    }

    if (typeName === 'PullRequest') {
      const pull = (value as { __type: 'PullRequest'; pull: PullRequest }).pull;
      const repo = (value as { __type: 'PullRequest'; repo: Repo }).repo;
      switch (field.name) {
        case 'id':
          return globalId('PullRequest', [repo.id, pull.number]);
        case 'databaseId':
          return pull.id;
        case 'number':
          return pull.number;
        case 'title':
          return pull.title;
        case 'body':
          return pull.body;
        case 'state':
          return pullStateGql(pull.state);
        case 'merged':
          return pull.merged;
        case 'mergeable':
          if (pull.state !== 'open') return 'UNKNOWN';
          return pullIsMergeable(repo, pull);
        case 'headRefName':
          return pull.headRef;
        case 'baseRefName':
          return pull.baseRef;
        case 'headRefOid':
          return pull.headSha;
        case 'baseRefOid':
          return pull.baseSha;
        case 'mergedAt':
          return pull.merged ? pull.mergedAt : null;
        case 'mergeCommitSha':
          return pull.merged ? pull.mergeCommitSha : null;
        case 'url':
          return `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`;
        case 'createdAt':
          return pull.createdAt;
        case 'author':
          return sub('User', { __type: 'User', login: VIEWER.login, id: VIEWER.id });
        case 'files': {
          const first = typeof args.first === 'number' ? args.first : 100;
          return sub('PullRequestFileConnection', { __type: 'PullRequestFileConnection', repo, pull, first });
        }
        default:
          return unknownField();
      }
    }

    if (typeName === 'IssueConnection') {
      const connection = value as { __type: 'IssueConnection'; repo: Repo; issues: Issue[]; endCursor: string | null; hasNextPage: boolean };
      if (field.name === 'nodes') {
        return connection.issues.map((issue) => {
          const out: Record<string, unknown> = {};
          this.executeSelections('Issue', { __type: 'Issue', repo: connection.repo, issue }, selections, variables, out);
          return out;
        });
      }
      if (field.name === 'edges') {
        return connection.issues.map((issue) => {
          const node: Record<string, unknown> = {};
          this.executeSelections('Issue', { __type: 'Issue', repo: connection.repo, issue }, selections, variables, node);
          return { node, cursor: cursorFor(issue.number) };
        });
      }
      if (field.name === 'pageInfo') {
        return sub('PageInfo', { __type: 'PageInfo', hasNextPage: connection.hasNextPage, endCursor: connection.endCursor });
      }
      if (field.name === 'totalCount') return connection.issues.length;
      return unknownField();
    }

    if (typeName === 'PullRequestConnection') {
      const connection = value as { __type: 'PullRequestConnection'; repo: Repo; pulls: PullRequest[] };
      if (field.name === 'nodes') {
        return connection.pulls.map((pull) => {
          const out: Record<string, unknown> = {};
          this.executeSelections('PullRequest', { __type: 'PullRequest', repo: connection.repo, pull }, selections, variables, out);
          return out;
        });
      }
      if (field.name === 'pageInfo') {
        return sub('PageInfo', { __type: 'PageInfo', hasNextPage: false, endCursor: null });
      }
      if (field.name === 'totalCount') return connection.pulls.length;
      return unknownField();
    }

    if (typeName === 'PullRequestFileConnection') {
      const connection = value as { __type: 'PullRequestFileConnection'; repo: Repo; pull: PullRequest; first: number };
      if (field.name === 'nodes') {
        const baseFiles = filesAtCommit(connection.repo, connection.pull.baseSha);
        const headFiles = filesAtCommit(connection.repo, connection.pull.headSha);
        const changes = diffFileMaps(connection.repo, baseFiles, headFiles).slice(0, connection.first);
        return changes.map((change) => {
          const out: Record<string, unknown> = {};
          for (const selection of selections) {
            if (selection.kind !== 'field') continue;
            const key = selection.field.alias ?? selection.field.name;
            if (selection.field.name === 'path') out[key] = change.path;
            else if (selection.field.name === 'additions') out[key] = change.additions;
            else if (selection.field.name === 'deletions') out[key] = change.deletions;
            else if (selection.field.name === 'changeType') out[key] = change.status.toUpperCase();
          }
          return out;
        });
      }
      if (field.name === 'pageInfo') {
        return sub('PageInfo', { __type: 'PageInfo', hasNextPage: false, endCursor: null });
      }
      if (field.name === 'totalCount') {
        const baseFiles = filesAtCommit(connection.repo, connection.pull.baseSha);
        const headFiles = filesAtCommit(connection.repo, connection.pull.headSha);
        return diffFileMaps(connection.repo, baseFiles, headFiles).length;
      }
      return unknownField();
    }

    if (typeName === 'PageInfo') {
      const info = value as { __type: 'PageInfo'; hasNextPage: boolean; endCursor: string | null };
      if (field.name === 'hasNextPage') return info.hasNextPage;
      if (field.name === 'hasPreviousPage') return false;
      if (field.name === 'endCursor') return info.endCursor;
      if (field.name === 'startCursor') return info.endCursor;
      return unknownField();
    }

    if (typeName === 'TypeInfo') {
      const info = value as { __type: 'TypeInfo'; name: string; fields: string[]; enumValues: string[] };
      if (field.name === 'name') return info.name;
      if (field.name === 'fields') return info.fields.map((name) => ({ name }));
      if (field.name === 'enumValues') return info.enumValues.map((name) => ({ name }));
      if (field.name === 'kind') return info.enumValues.length > 0 ? 'ENUM' : 'OBJECT';
      return unknownField();
    }

    if (typeName === 'Ref') {
      const ref = value as { __type: 'Ref'; name: string };
      if (field.name === 'name') return ref.name;
      return unknownField();
    }

    if (typeName === 'CommentEdge') {
      const edge = value as { __type: 'CommentEdge'; comment: Comment };
      if (field.name === 'node') {
        const out: Record<string, unknown> = {};
        for (const selection of selections) {
          if (selection.kind !== 'field') continue;
          const key = selection.field.alias ?? selection.field.name;
          if (selection.field.name === 'id') out[key] = globalId('IssueComment', [edge.repo.id, edge.issue.number, edge.comment.id]);
          else if (selection.field.name === 'body') out[key] = edge.comment.body;
        }
        return out;
      }
      if (field.name === 'cursor') return cursorFor(edge.comment.id);
      return unknownField();
    }

    return unknownField();
  }

  private payloadIssue(issue: Issue, repo: Repo, selections: readonly GqlSelection[], variables: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const selection of selections) {
      if (selection.kind !== 'field') continue;
      const key = selection.field.alias ?? selection.field.name;
      if (selection.field.name === 'issue') {
        const issueOut: Record<string, unknown> = {};
        this.executeSelections('Issue', { __type: 'Issue', repo, issue }, selection.field.selections, variables, issueOut);
        out[key] = issueOut;
      }
    }
    return out;
  }

  private payloadPull(pull: PullRequest, repo: Repo, selections: readonly GqlSelection[], variables: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const selection of selections) {
      if (selection.kind !== 'field') continue;
      const key = selection.field.alias ?? selection.field.name;
      if (selection.field.name === 'pullRequest') {
        const pullOut: Record<string, unknown> = {};
        this.executeSelections('PullRequest', { __type: 'PullRequest', repo, pull }, selection.field.selections, variables, pullOut);
        out[key] = pullOut;
      }
    }
    return out;
  }
}

/** Run one GraphQL operation document (or a batch array) and return the response body. */
function handleGraphQL(bodyText: string): { status: number; body: unknown } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return { status: 400, body: { message: 'Invalid JSON' } };
  }
  const runOne = (operation: unknown): Record<string, unknown> => {
    if (!isRecord(operation) || typeof operation.query !== 'string') {
      return { data: null, errors: [{ message: 'A query string is required.' }] };
    }
    const variables = isRecord(operation.variables) ? (operation.variables as Record<string, unknown>) : {};
    let operations: GqlOperation[];
    let fragments = new Map<string, GqlSelection[]>();
    try {
      const parser = new GqlParser(operation.query);
      operations = parser.parseDocument();
      fragments = parser.fragments;
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'Could not parse the query.' }] };
    }
    if (operations.length === 0) return { data: null, errors: [{ message: 'The document holds no operation.' }] };
    const chosen = operations.find((op) => op.name === operation.operationName) ?? operations[0];
    if (chosen === undefined) return { data: null, errors: [{ message: 'No operation to run.' }] };
    const executor = new GqlExecutor(fragments);
    const result = executor.execute(chosen, variables);
    const body: Record<string, unknown> = { data: result.data };
    if (result.errors.length > 0) body.errors = result.errors;
    return body;
  };
  if (Array.isArray(parsed)) {
    return { status: 200, body: parsed.map((operation) => runOne(operation)) };
  }
  return { status: 200, body: runOne(parsed) };
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 over streamable HTTP, modern (server/discover) and legacy
// (initialize) handshakes, six tools over the same store as REST.
// ---------------------------------------------------------------------------

const MCP_SERVER_INFO = { name: 'forge', version: FORGE_VERSION };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, Record<string, unknown>>;
    required: string[];
  };
}

const MCP_TOOLS: readonly McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'open, closed or all.', enum: ['open', 'closed', 'all'] },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch onto a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function normalizeArgName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function mcpArg(args: Record<string, unknown>, ...synonyms: readonly string[]): unknown {
  const byNormalized = new Map<string, unknown>();
  for (const [key, value] of Object.entries(args)) byNormalized.set(normalizeArgName(key), value);
  for (const synonym of synonyms) {
    const found = byNormalized.get(normalizeArgName(synonym));
    if (found !== undefined) return found;
  }
  return undefined;
}

function mcpRepoFromArgs(args: Record<string, unknown>): Repo | null {
  let owner = mcpArg(args, 'owner', 'owner_login', 'org', 'user', 'login', 'account') as string | undefined;
  let repoName = mcpArg(args, 'repo', 'repository', 'repository_name', 'repo_name') as string | undefined;
  if ((owner === undefined || repoName === undefined) && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) {
      owner = parts[0];
      repoName = parts[1];
    }
  }
  if (typeof owner !== 'string' || typeof repoName !== 'string') return null;
  return findRepo(owner, repoName);
}

function mcpToolResult(payload: unknown, isError: boolean): Record<string, unknown> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return {
    content: [{ type: 'text', text }],
    structuredContent: isRecord(payload) ? payload : { result: payload },
    isError,
  };
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (tool === undefined) {
    return mcpToolResult({ error: `Unknown tool: ${name}` }, true);
  }
  for (const required of tool.inputSchema.required) {
    if (mcpArg(args, required) === undefined) {
      return mcpToolResult({ error: `Missing required argument: ${required}` }, true);
    }
  }

  if (name === 'create_repo') {
    const repoName = mcpArg(args, 'name', 'repo', 'repository') as string;
    if (repos.has(repoKey(VIEWER.login, repoName))) {
      return mcpToolResult({ error: `Repository '${repoName}' already exists` }, true);
    }
    const description = (mcpArg(args, 'description', 'about', 'summary', 'body') as string | undefined) ?? '';
    const isPrivate = (mcpArg(args, 'private', 'is_private') as boolean | undefined) ?? false;
    const repo = createRepoRecord(repoName, isPrivate === true, description, 'main');
    return mcpToolResult(repoJson(repo), false);
  }

  if (name === 'get_repo') {
    const repo = mcpRepoFromArgs(args);
    if (repo === null) return mcpToolResult({ error: 'Repository not found' }, true);
    return mcpToolResult(repoJson(repo), false);
  }

  if (name === 'create_issue') {
    const repo = mcpRepoFromArgs(args);
    if (repo === null) return mcpToolResult({ error: 'Repository not found' }, true);
    const title = mcpArg(args, 'title', 'issue_title', 'subject') as string;
    const body = (mcpArg(args, 'body', 'issue_body', 'description', 'content', 'text') as string | undefined) ?? '';
    const issue = createIssueRecord(repo, title, body);
    return mcpToolResult(issueJson(repo, issue), false);
  }

  if (name === 'list_issues') {
    const repo = mcpRepoFromArgs(args);
    if (repo === null) return mcpToolResult({ error: 'Repository not found' }, true);
    const state = (mcpArg(args, 'state', 'status') as string | undefined) ?? 'open';
    let list = [...repo.issues.values()];
    if (state === 'open') list = list.filter((issue) => issue.state === 'open');
    else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
    list.sort((a, b) => b.seq - a.seq);
    const payload = { issues: list.map((issue) => issueJson(repo, issue)), count: list.length };
    return mcpToolResult(payload, false);
  }

  if (name === 'create_pull_request') {
    const repo = mcpRepoFromArgs(args);
    if (repo === null) return mcpToolResult({ error: 'Repository not found' }, true);
    const title = mcpArg(args, 'title', 'pr_title', 'pull_request_title', 'subject') as string;
    const head = mcpArg(args, 'head', 'head_ref', 'head_branch', 'source', 'source_branch', 'from_branch', 'branch') as string;
    const base = mcpArg(args, 'base', 'base_ref', 'base_branch', 'target', 'target_branch', 'into_branch') as string;
    const body = (mcpArg(args, 'body', 'description', 'content', 'text') as string | undefined) ?? '';
    const pull = createPullRecord(repo, title, body, head, base);
    if (pull === null) return mcpToolResult({ error: 'Could not create the pull request: the head or base branch does not exist, or a pull request is already open.' }, true);
    return mcpToolResult(pullJson(repo, pull), false);
  }

  if (name === 'merge_pull_request') {
    const repo = mcpRepoFromArgs(args);
    if (repo === null) return mcpToolResult({ error: 'Repository not found' }, true);
    const pullNumber = mcpArg(args, 'pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index') as number;
    const pull = repo.pulls.get(Number(pullNumber));
    if (pull === undefined) return mcpToolResult({ error: 'Pull request not found' }, true);
    const result = mergePullRecord(repo, pull);
    if (!result.ok) return mcpToolResult({ error: result.reason ?? 'Could not merge' }, true);
    return mcpToolResult({ merged: true, sha: pull.mergeCommitSha, message: `Merge pull request #${pull.number}`, number: pull.number }, false);
  }

  return mcpToolResult({ error: `Unknown tool: ${name}` }, true);
}

function jsonRpcResult(id: unknown, result: unknown, extraHeaders: Record<string, string> = {}): { status: number; body: unknown; headers: Record<string, string> } {
  return { status: 200, body: { jsonrpc: '2.0', id, result }, headers: extraHeaders };
}
function jsonRpcError(id: unknown, code: number, message: string): { status: number; body: unknown; headers: Record<string, string> } {
  return { status: 200, body: { jsonrpc: '2.0', id, error: { code, message } }, headers: {} };
}

function handleMcpRequest(parsed: unknown): { status: number; body: unknown; headers: Record<string, string> } | null {
  if (!isRecord(parsed)) return null;
  const id = 'id' in parsed ? parsed.id : undefined;
  const method = parsed.method;
  if (typeof method !== 'string') return null;
  // A notification (no id) is answered with 202 and no body.
  if (id === undefined) return { status: 202, body: null, headers: {} };
  const params = isRecord(parsed.params) ? (parsed.params as Record<string, unknown>) : {};

  if (method === 'server/discover') {
    const result = {
      supportedVersions: MCP_SUPPORTED_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
      _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
    };
    return jsonRpcResult(id, result);
  }
  if (method === 'initialize') {
    const requested = params.protocolVersion as string | undefined;
    const protocolVersion =
      typeof requested === 'string' && (MCP_SUPPORTED_VERSIONS.includes(requested) || MCP_LEGACY_VERSIONS.includes(requested))
        ? requested
        : '2025-11-25';
    return jsonRpcResult(
      id,
      { protocolVersion, capabilities: { tools: {} }, serverInfo: MCP_SERVER_INFO },
      { 'mcp-session-id': 'forge-session-1' },
    );
  }
  if (method === 'ping') return jsonRpcResult(id, {});
  if (method === 'tools/list') {
    return jsonRpcResult(id, { tools: MCP_TOOLS });
  }
  if (method === 'tools/call') {
    const toolName = params.name as string | undefined;
    const toolArgs = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    if (typeof toolName !== 'string' || toolName === '') {
      return jsonRpcError(id, -32602, 'tools/call needs a tool name');
    }
    const known = MCP_TOOLS.some((tool) => tool.name === toolName);
    if (!known) return jsonRpcError(id, -32602, `Unknown tool: ${toolName}`);
    const result = mcpCallTool(toolName, toolArgs);
    return jsonRpcResult(id, result);
  }
  return jsonRpcError(id, -32601, `Method not found: ${method}`);
}

function handleMcp(req: IncomingMessage, res: ServerResponse, bodyText: string): void {
  const method = req.method ?? 'POST';
  if (method === 'DELETE') {
    sendEmpty(res, 204);
    return;
  }
  if (method !== 'POST') {
    sendError(res, 405, 'Method Not Allowed');
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  if (Array.isArray(parsed)) {
    const answers: unknown[] = [];
    for (const item of parsed) {
      const answer = handleMcpRequest(item);
      if (answer !== null && answer.body !== null) answers.push(answer.body);
    }
    return sendJson(res, 200, answers);
  }
  const answer = handleMcpRequest(parsed);
  if (answer === null) {
    return sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  if (answer.body === null) {
    sendEmpty(res, answer.status);
    return;
  }
  return sendJson(res, answer.status, answer.body, answer.headers);
}

// ---------------------------------------------------------------------------
// The server: health, git, REST, GraphQL, MCP, and a JSON 404 for the rest.
// ---------------------------------------------------------------------------

function sendRaw(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(),
  });
  res.end(body);
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const segments = pathSegments(req);
  const method = req.method ?? 'GET';

  if (method === 'GET' && segments.length === 1 && segments[0] === 'healthz') {
    sendJson(res, 200, { ok: true });
    return;
  }

  // Git smart HTTP: /{owner}/{repo}.git/...
  if (segments.length >= 2 && (segments[1] as string).endsWith('.git')) {
    const owner = segments[0] as string;
    const repoName = (segments[1] as string).slice(0, -'.git'.length);
    if (!isAuthorized(req)) {
      sendError(res, 401, 'Bad credentials');
      return;
    }
    const repo = findRepo(owner, repoName);
    const tail = segments.slice(2).join('/');
    const query = parseQuery(req);
    if (method === 'GET' && tail === 'info/refs') {
      if (repo === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const service = query.get('service');
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendError(res, 404, 'Not Found');
        return;
      }
      const protocol = req.headers['git-protocol'] === 'version=2' && service === 'git-upload-pack' ? 2 : 0;
      const body = advertisementBody(repo, service, protocol);
      sendRaw(res, 200, `application/x-${service}-advertisement`, body);
      return;
    }
    if (method === 'POST' && tail === 'git-upload-pack') {
      if (repo === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const raw = await readBody(req);
      try {
        if (req.headers['git-protocol'] === 'version=2') {
          const { command, args } = parseV2Request(raw);
          if (command === 'ls-refs') {
            sendRaw(res, 200, 'application/x-git-upload-pack-result', handleLsRefsV2(repo, args));
            return;
          }
          if (command === 'fetch') {
            sendRaw(res, 200, 'application/x-git-upload-pack-result', handleFetchV2(repo, args));
            return;
          }
          sendError(res, 400, `Unknown git-upload-pack command: ${command}`);
          return;
        }
        sendRaw(res, 200, 'application/x-git-upload-pack-result', handleFetchV0(repo, raw));
      } catch (err) {
        sendError(res, 400, err instanceof Error ? err.message : 'Bad request');
      }
      return;
    }
    if (method === 'POST' && tail === 'git-receive-pack') {
      if (repo === null) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const raw = await readBody(req);
      try {
        sendRaw(res, 200, 'application/x-git-receive-pack-result', handleReceivePack(repo, raw));
      } catch (err) {
        sendError(res, 400, err instanceof Error ? err.message : 'Bad request');
      }
      return;
    }
    sendError(res, 404, 'Not Found');
    return;
  }

  // MCP.
  if (segments.length === 1 && segments[0] === 'mcp') {
    if (!isAuthorized(req)) {
      sendError(res, 401, 'Bad credentials');
      return;
    }
    const raw = method === 'POST' ? await readBody(req) : Buffer.alloc(0);
    handleMcp(req, res, raw.toString('utf8'));
    return;
  }

  // GraphQL.
  if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
    if (method !== 'POST') {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (!isAuthorized(req)) {
      sendError(res, 401, 'Bad credentials');
      return;
    }
    const raw = await readBody(req);
    const answer = handleGraphQL(raw.toString('utf8'));
    sendJson(res, answer.status, answer.body);
    return;
  }

  // REST v3.
  if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
    if (!isAuthorized(req)) {
      sendError(res, 401, 'Bad credentials');
      return;
    }
    const restSegments = segments.slice(2);
    let parsedBody: JsonRecord | null = null;
    if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
      const raw = await readBody(req);
      if (raw.length > 0) {
        try {
          const value: unknown = JSON.parse(raw.toString('utf8'));
          if (!isRecord(value)) {
            sendError(res, 400, 'Invalid JSON');
            return;
          }
          parsedBody = value;
        } catch {
          sendError(res, 400, 'Invalid JSON');
          return;
        }
      }
    }
    handleRest(req, res, restSegments, parseQuery(req), parsedBody);
    return;
  }

  sendError(res, 404, 'Not Found');
}

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleRequest(req, res).catch((err: unknown) => {
      try {
        if (!res.headersSent) sendError(res, 500, err instanceof Error ? err.message : 'Internal Server Error');
        else res.end();
      } catch {
        // The socket is already gone; nothing left to do.
      }
    });
  });
  server.keepAliveTimeout = 30_000;
  return server;
}
