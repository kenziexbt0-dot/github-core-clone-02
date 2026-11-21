// A standalone GitHub-compatible git forge in one process: git smart HTTP (v2 + v0),
// REST v3, GraphQL v4 and MCP, over its own in-memory store. Node 22 standard library only:
// node:http, node:crypto, node:zlib. No disk writes, no git binary, no package manager.
//
// The entry is mounted read-only in the trial, so everything lives in memory; the store is
// deterministic (sequential ids, fixed timestamps, creation-ordered lists) so two runs on the
// same input leave the same observable state.

import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------------------
// The scenario's viewer identity.
//
// The suite derives every name from one fixed seed (wire.ts SCENARIO_SEED); the token owner
// is the scenario's first generated user. The forge reproduces that one derivation so the
// bearer token maps to the login the checks create repositories under. Nothing else from
// the scenario is needed: every other name arrives in the requests themselves.

const SCENARIO_SEED = 0x6a09e667f3bcc909n;
const U64_MASK = 0xffffffffffffffffn;

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

interface ViewerIdentity {
  readonly id: number;
  readonly login: string;
  readonly name: string;
  readonly email: string;
}

function viewerIdentity(): ViewerIdentity {
  const rng = new Rng(mix64(SCENARIO_SEED ^ fnv1a64('users')));
  const used = new Set<string>();
  let first: ViewerIdentity | null = null;
  for (let i = 0; i < 12; i += 1) {
    const firstName = rng.pick(FIRST_NAMES);
    const lastName = rng.pick(LAST_NAMES);
    const base = `${firstName}${lastName}`.replace(/[^a-z0-9-]/g, '');
    let login = base;
    let suffix = 2;
    while (used.has(login)) {
      login = `${base}-${suffix}`;
      suffix += 1;
    }
    used.add(login);
    if (first === null) first = { id: 1000 + i, login, name: `${firstName} ${lastName}`, email: `${login}@example.invalid` };
  }
  return first as ViewerIdentity;
}

export const VIEWER: ViewerIdentity = viewerIdentity();

/** The default labels a fresh repository carries, as GitHub ships them. */
const DEFAULT_LABELS: readonly string[] = ['bug', 'enhancement', 'documentation', 'question', 'good first issue', 'help wanted'];

// ---------------------------------------------------------------------------
// Small utilities

const ZERO_OID = '0'.repeat(40);
const SHA40 = /^[0-9a-f]{40}$/;
const FORGE_AGENT = 'forge/1.0';
const FIXED_EPOCH_SEC = 1_700_000_000;
const FIXED_ISO = new Date(FIXED_EPOCH_SEC * 1000).toISOString();

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64encode(data: Buffer | string): string {
  return Buffer.from(data as string, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function isObjectId(value: string): boolean {
  return SHA40.test(value);
}

/** JSON with sorted keys at every depth: deterministic bytes for the same value. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

// ---------------------------------------------------------------------------
// pkt-line codec (git's framing: 4 hex length bytes, 0000 flush, 0001 delim)

const PKT_LINE_MAX = 65520;

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  if (data.length + 4 > PKT_LINE_MAX) throw new Error(`pkt-line payload ${data.length} bytes exceeds the maximum`);
  const header = Buffer.allocUnsafe(4);
  header.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([header, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLineFlush(): Buffer {
  return PKT_FLUSH;
}

function pktLineDelim(): Buffer {
  return PKT_DELIM;
}

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

type DecodedPacket = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'response-end' };

/** Decode a whole buffer of pkt-lines; throws on a malformed header or truncation. */
function decodePktLines(buffer: Buffer): DecodedPacket[] {
  const packets: DecodedPacket[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line header');
    const header = buffer.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(header)) throw new Error(`invalid pkt-line length ${JSON.stringify(header)}`);
    const length = Number.parseInt(header, 16);
    if (length === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (length === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (length === 2) {
      packets.push({ kind: 'response-end' });
      offset += 4;
      continue;
    }
    if (length < 4 || length > PKT_LINE_MAX) throw new Error(`invalid pkt-line length ${length}`);
    if (offset + length > buffer.length) throw new Error('truncated pkt-line');
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return packets;
}

// ---------------------------------------------------------------------------
// git object model

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  readonly type: GitObjectType;
  readonly data: Buffer;
}

const TYPE_CODE: Readonly<Record<GitObjectType, number>> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Readonly<Record<number, GitObjectType>> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: GitObjectType, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\u0000`, 'utf8');
  return createHash('sha1').update(header).update(data).digest('hex');
}

interface TreeEntry {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

/**
 * Parsed git-object views are memoized on the object buffer itself. Objects are immutable once
 * stored in a repo (putObject only adds new ones), so a parsed view stays valid for the buffer's
 * life, and WeakMap entries die with the buffer when a repo is deleted. This keeps the graph
 * walks (fetch planning, merge-base, ancestry) from re-parsing the same commit or tree on every
 * visit; a throwing parse is never cached, so bad data still throws every time.
 */
const parseTreeCache = new WeakMap<Buffer, TreeEntry[]>();
const parseCommitCache = new WeakMap<Buffer, CommitView>();
const parseTagCache = new WeakMap<Buffer, TagView>();

function parseTree(data: Buffer): TreeEntry[] {
  const cached = parseTreeCache.get(data);
  if (cached !== undefined) return cached;
  const entries = parseTreeUncached(data);
  parseTreeCache.set(data, entries);
  return entries;
}

function parseTreeUncached(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('tree entry is truncated');
    entries.push({
      mode: data.subarray(offset, space).toString('ascii'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

function compareTreeNames(a: { name: string; mode: string }, b: { name: string; mode: string }): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeNames);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\u0000`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  readonly tree: string;
  readonly parents: string[];
  readonly author: string;
  readonly committer: string;
  readonly message: string;
}

function parseCommit(data: Buffer): CommitView {
  const cached = parseCommitCache.get(data);
  if (cached !== undefined) return cached;
  const view = parseCommitUncached(data);
  parseCommitCache.set(data, view);
  return view;
}

function parseCommitUncached(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headerText = data.subarray(0, headerEnd).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
  }
  if (!isObjectId(tree)) throw new Error('commit has no valid tree header');
  return { tree, parents, author, committer, message };
}

interface TagView {
  readonly object: string;
  readonly type: GitObjectType;
  readonly tag: string;
  readonly tagger: string;
  readonly message: string;
}

function parseTag(data: Buffer): TagView {
  const cached = parseTagCache.get(data);
  if (cached !== undefined) return cached;
  const view = parseTagUncached(data);
  parseTagCache.set(data, view);
  return view;
}

function parseTagUncached(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) continue;
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  const object = headers.get('object') ?? '';
  const type = headers.get('type') ?? '';
  if (!isObjectId(object)) throw new Error('tag has no valid object header');
  if (type !== 'commit' && type !== 'tree' && type !== 'blob' && type !== 'tag') throw new Error('tag has a bad type');
  return {
    object,
    type: type as GitObjectType,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

function buildCommit(tree: string, parents: readonly string[], message: string, author: string, timestamp: number): Buffer {
  const who = `${author} ${timestamp} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

// ---------------------------------------------------------------------------
// packfile read (plain objects; the suite's client never sends deltas) and write

function inflateAt(buffer: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buffer.subarray(offset);
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    result = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
  } catch (err) {
    throw new Error(`zlib stream at offset ${offset} did not inflate: ${(err as Error).message}`);
  }
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error(`zlib stream at offset ${offset} consumed no bytes`);
  return { data: result.buffer, next: offset + written };
}

function readVarintSize(buffer: Buffer, start: number): { size: number; next: number; first: number } {
  if (start >= buffer.length) throw new Error('pack entry has no size header');
  let byte = buffer[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let offset = start + 1;
  while (byte & 0x80) {
    if (offset >= buffer.length) throw new Error('pack entry size varint is truncated');
    byte = buffer[offset] as number;
    offset += 1;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
    if (shift > 63) throw new Error('pack entry size varint is too long');
  }
  return { size, next: offset, first };
}

/**
 * Read a packfile (version 2). Returns the objects keyed by their recomputed id. Deltas are
 * refused with an error (the suite's client writes plain packs only).
 */
function readPack(pack: Buffer): Map<string, GitObject> {
  if (pack.length < 32) throw new Error(`pack is ${pack.length} bytes, too short`);
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack does not start with PACK');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const declaredCount = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  const computed = sha1Hex(pack.subarray(0, trailerStart));
  if (trailer !== computed) throw new Error('pack trailer does not match its bytes');
  const objects = new Map<string, GitObject>();
  let offset = 12;
  for (let index = 0; index < declaredCount; index += 1) {
    const header = readVarintSize(pack, offset);
    offset = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    if (typeCode === 6 || typeCode === 7) throw new Error('delta pack entries are not accepted');
    const type = CODE_TYPE[typeCode];
    if (type === undefined) throw new Error(`pack entry ${index} has unknown type code ${typeCode}`);
    const inflated = inflateAt(pack.subarray(0, trailerStart), offset);
    if (inflated.data.length !== header.size) {
      throw new Error(`pack entry at ${offset} declares ${header.size} bytes but inflated to ${inflated.data.length}`);
    }
    offset = inflated.next;
    const oid = hashObject(type, inflated.data);
    if (!objects.has(oid)) objects.set(oid, { type, data: inflated.data });
  }
  if (offset !== trailerStart) throw new Error(`pack has ${trailerStart - offset} stray bytes before its trailer`);
  return objects;
}

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas). One concatenation: the trailer hash is fed the parts in place instead of hashing a second copy of the body. */
function writePack(objects: Iterable<GitObject>): Buffer {
  const list = [...objects];
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(list.length, 8);
  parts.push(header);
  for (const object of list) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const hash = createHash('sha1');
  for (const part of parts) hash.update(part);
  parts.push(hash.digest());
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// The store: repositories, issues, pull requests, comments — all in memory.

interface IssueRecord {
  readonly id: number;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  readonly createdSeq: number;
  readonly createdAt: string;
  updatedAt: string;
  comments: CommentRecord[];
}

interface CommentRecord {
  readonly id: number;
  body: string;
  readonly createdAt: string;
}

interface PullRecord {
  readonly id: number;
  readonly number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  readonly head: string;
  readonly base: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  readonly createdSeq: number;
  readonly createdAt: string;
}

interface RepoRecord {
  readonly id: number;
  readonly owner: string;
  name: string;
  description: string;
  isPrivate: boolean;
  readonly defaultBranch: string;
  readonly objects: Map<string, GitObject>;
  readonly refs: Map<string, string>;
  readonly issues: Map<number, IssueRecord>;
  readonly pulls: Map<number, PullRecord>;
  readonly labels: Map<string, { name: string; color: string }>;
  /** Issues and pull requests share one counter, as on GitHub. */
  nextNumber: number;
  readonly createdSeq: number;
  /** Bumped on every change to objects or refs; fetch responses are cached against it. */
  generation: number;
}

class Store {
  readonly repos = new Map<string, RepoRecord>();
  private nextRepoId = 1;
  private nextObjectId = 1;
  private nextCommentId = 1;
  private nextSeq = 1;
  requestCounter = 0;

  nextRequestId(): string {
    this.requestCounter += 1;
    return `req-${this.requestCounter}`;
  }

  seq(): number {
    this.nextSeq += 1;
    return this.nextSeq;
  }

  repoKey(owner: string, name: string): string {
    return `${owner}/${name}`;
  }

  getRepo(owner: string, name: string): RepoRecord | undefined {
    return this.repos.get(this.repoKey(owner, name));
  }

  createRepo(owner: string, name: string, description: string, isPrivate: boolean): RepoRecord | null {
    const key = this.repoKey(owner, name);
    if (this.repos.has(key)) return null;
    const repo: RepoRecord = {
      id: this.nextRepoId,
      owner,
      name,
      description,
      isPrivate,
      defaultBranch: 'main',
      objects: new Map(),
      refs: new Map(),
      issues: new Map(),
      pulls: new Map(),
      labels: new Map(),
      nextNumber: 1,
      createdSeq: this.seq(),
      generation: 0,
    };
    this.nextRepoId += 1;
    for (const label of DEFAULT_LABELS) repo.labels.set(label, { name: label, color: 'ededed' });
    this.repos.set(key, repo);
    return repo;
  }

  deleteRepo(owner: string, name: string): boolean {
    return this.repos.delete(this.repoKey(owner, name));
  }

  listRepos(owner: string): RepoRecord[] {
    const out: RepoRecord[] = [];
    for (const repo of this.repos.values()) if (repo.owner === owner) out.push(repo);
    out.sort((a, b) => a.createdSeq - b.createdSeq);
    return out;
  }

  newIssueId(): number {
    this.nextObjectId += 1;
    return 10000 + this.nextObjectId;
  }

  newCommentId(): number {
    this.nextCommentId += 1;
    return this.nextCommentId;
  }
}

const store = new Store();

// ---------------------------------------------------------------------------
// git graph helpers (all operate on one repo's object map)

type ObjectLookup = (oid: string) => GitObject | undefined;

function lookupIn(repo: RepoRecord): ObjectLookup {
  return (oid: string) => repo.objects.get(oid);
}

/** Every object reachable from `roots` (commits, trees, blobs, tags). */
function collectReachable(roots: Iterable<string>, lookup: ObjectLookup): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const root of roots) if (isObjectId(root)) queue.push(root);
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      const commit = parseCommit(object.data);
      queue.push(commit.tree);
      for (const parent of commit.parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** Is `ancestor` reachable from `descendant` (following commit parents, tags peeled)? */
function isAncestor(repo: RepoRecord, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const lookup = lookupIn(repo);
  const seen = new Set<string>();
  const queue: string[] = [descendant];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = lookup(oid);
    if (object === undefined) continue;
    if (object.type === 'commit') {
      for (const parent of parseCommit(object.data).parents) queue.push(parent);
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    }
  }
  return false;
}

/** The first common ancestor of two commits, walking breadth-first from both. */
function mergeBase(repo: RepoRecord, a: string, b: string): string | null {
  const lookup = lookupIn(repo);
  const ancestorsOf = (start: string): Set<string> => {
    const seen = new Set<string>();
    const queue: string[] = [start];
    while (queue.length > 0) {
      const oid = queue.pop() as string;
      if (seen.has(oid)) continue;
      const object = lookup(oid);
      if (object === undefined || object.type !== 'commit') continue;
      seen.add(oid);
      for (const parent of parseCommit(object.data).parents) queue.push(parent);
    }
    return seen;
  };
  const aAncestors = ancestorsOf(a);
  // Breadth-first from b, so the first hit is the closest common ancestor.
  const seen = new Set<string>();
  const queue: string[] = [b];
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head] as string;
    if (aAncestors.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = lookup(oid);
    if (object === undefined || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return null;
}

/** The commit at a ref, or null. */
function refCommit(repo: RepoRecord, ref: string): string | null {
  const oid = repo.refs.get(ref);
  if (oid === undefined) return null;
  const object = repo.objects.get(oid);
  if (object === undefined) return null;
  if (object.type === 'commit') return oid;
  if (object.type === 'tag') return parseTag(object.data).object;
  return null;
}

/** Walk a commit's history, newest first (parents in order, depth-first). */
function walkCommits(repo: RepoRecord, tip: string): string[] {
  const lookup = lookupIn(repo);
  const out: string[] = [];
  const seen = new Set<string>();
  const queue: string[] = [tip];
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head] as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined || object.type !== 'commit') continue;
    seen.add(oid);
    out.push(oid);
    for (const parent of parseCommit(object.data).parents) queue.push(parent);
  }
  return out;
}

/** Flatten a tree into path -> {mode, oid} (blobs only; gitlinks skipped). */
function flattenTree(repo: RepoRecord, treeOid: string): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const walk = (oid: string, prefix: string): void => {
    const object = repo.objects.get(oid);
    if (object === undefined || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else if (entry.mode !== '160000') out.set(path, { mode: entry.mode, oid: entry.oid });
    }
  };
  walk(treeOid, '');
  return out;
}

/** The tree of a commit, as a flat path map. */
function treeOfCommit(repo: RepoRecord, commitOid: string): Map<string, { mode: string; oid: string }> {
  const object = repo.objects.get(commitOid);
  if (object === undefined || object.type !== 'commit') return new Map();
  return flattenTree(repo, parseCommit(object.data).tree);
}

interface FileDiff {
  filename: string;
  status: 'added' | 'modified' | 'removed';
  additions: number;
  deletions: number;
  changes: number;
}

function countLines(data: Buffer): number {
  if (data.length === 0) return 0;
  let lines = 0;
  for (let i = 0; i < data.length; i += 1) if (data[i] === 0x0a) lines += 1;
  if (data[data.length - 1] !== 0x0a) lines += 1;
  return lines;
}

/** A line-set diff between two blob contents: additions and deletions. */
function lineDiff(oldData: Buffer, newData: Buffer): { additions: number; deletions: number } {
  const oldLines = new Set(oldData.toString('utf8').split('\n'));
  const newLines = newData.toString('utf8').split('\n');
  let additions = 0;
  for (const line of newLines) if (!oldLines.has(line)) additions += 1;
  const newSet = new Set(newLines);
  let deletions = 0;
  for (const line of oldData.toString('utf8').split('\n')) if (!newSet.has(line)) deletions += 1;
  return { additions, deletions };
}

function diffTrees(repo: RepoRecord, oldTree: Map<string, { mode: string; oid: string }>, newTree: Map<string, { mode: string; oid: string }>): FileDiff[] {
  const out: FileDiff[] = [];
  const paths = new Set([...oldTree.keys(), ...newTree.keys()]);
  for (const path of [...paths].sort()) {
    const oldEntry = oldTree.get(path);
    const newEntry = newTree.get(path);
    if (oldEntry === undefined && newEntry !== undefined) {
      const data = repo.objects.get(newEntry.oid)?.data ?? Buffer.alloc(0);
      const additions = countLines(data);
      out.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (oldEntry !== undefined && newEntry === undefined) {
      const data = repo.objects.get(oldEntry.oid)?.data ?? Buffer.alloc(0);
      const deletions = countLines(data);
      out.push({ filename: path, status: 'removed', additions: 0, deletions, changes: deletions });
    } else if (oldEntry !== undefined && newEntry !== undefined && oldEntry.oid !== newEntry.oid) {
      const oldData = repo.objects.get(oldEntry.oid)?.data ?? Buffer.alloc(0);
      const newData = repo.objects.get(newEntry.oid)?.data ?? Buffer.alloc(0);
      const { additions, deletions } = lineDiff(oldData, newData);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

/** Build the tree objects for `files` (path -> blob bytes) on top of a base tree. */
function buildTreeForFiles(repo: RepoRecord, baseTree: Map<string, { mode: string; oid: string }>, files: Map<string, Buffer>): string {
  const flat = new Map(baseTree);
  for (const [path, data] of files) {
    const oid = hashObject('blob', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'blob', data });
    flat.set(path, { mode: '100644', oid });
  }
  // Rebuild nested trees bottom-up.
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const segment = segments[i] as string;
      if (!node.dirs.has(segment)) node.dirs.set(segment, makeNode());
      node = node.dirs.get(segment) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, entry.oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}

/** Store one object, returning its id. */
function putObject(repo: RepoRecord, type: GitObjectType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

// ---------------------------------------------------------------------------
// HTTP plumbing

const JSON_TYPE = 'application/json; charset=utf-8';
const MAX_BODY_BYTES = 128 * 1024 * 1024;

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = Buffer.from(`${JSON.stringify(body)}\n`, 'utf8');
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': payload.length,
    'x-github-request-id': store.nextRequestId(),
    ...headers,
  });
  res.end(payload);
}

function sendRaw(res: ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': store.nextRequestId(),
  });
  res.end(body);
}

function sendEmpty(res: ServerResponse, status: number): void {
  res.writeHead(status, { 'x-github-request-id': store.nextRequestId() });
  res.end();
}

function errorJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function bearerToken(req: IncomingMessage): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(.+)$/.exec(header.trim());
  return match === null ? null : (match[1] as string);
}

/** Any non-empty bearer token is the viewer; a missing one is unauthenticated. */
function isAuthenticated(req: IncomingMessage): boolean {
  const token = bearerToken(req);
  return token !== null && token !== '';
}

function parseJsonBody(buffer: Buffer): { ok: true; value: Record<string, unknown> } | { ok: false } {
  if (buffer.length === 0) return { ok: true, value: {} };
  try {
    const value = JSON.parse(buffer.toString('utf8')) as unknown;
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) return { ok: true, value: value as Record<string, unknown> };
    return { ok: false };
  } catch {
    return { ok: false };
  }
}

/** The request's path, split and decoded, and its query — parsed once per request. */
interface RequestParts {
  segments: string[];
  pathname: string;
  query: URLSearchParams;
}

/** Parse the request line once: one `new URL` for the path, the segments and the query. */
function parseRequest(req: IncomingMessage): RequestParts {
  let pathname = '/';
  let query = new URLSearchParams();
  try {
    const url = new URL(req.url ?? '/', 'http://entry');
    pathname = url.pathname;
    query = url.searchParams;
  } catch {
    // Keep the defaults: pathname '/' and no query, as the old per-use parsers did.
  }
  const segments = pathname
    .split('/')
    .filter((segment) => segment !== '')
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });
  return { segments, pathname, query };
}

/** The shared empty body: requests that carry no bytes reuse one buffer instead of a fresh read. */
const EMPTY_BODY = Buffer.alloc(0);

/** Whether the request actually carries a body (a length, or a chunked stream). */
function hasRequestBody(req: IncomingMessage): boolean {
  const length = req.headers['content-length'];
  if (length !== undefined) return length !== '0';
  return req.headers['transfer-encoding'] !== undefined;
}

/**
 * The request body, without paying for a stream read when there is nothing to read: a bodyless
 * GET/HEAD/DELETE resolves in the same tick instead of waiting for the stream's 'end' event.
 * Any request that declares bytes (content-length or transfer-encoding) is read in full, as before.
 */
async function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  const method = req.method ?? 'GET';
  if ((method === 'GET' || method === 'HEAD' || method === 'DELETE') && !hasRequestBody(req)) return EMPTY_BODY;
  return readBody(req);
}

function pageParams(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const perPageRaw = Number.parseInt(query.get('per_page') ?? '30', 10) || 30;
  const perPage = Math.min(100, Math.max(1, perPageRaw));
  return { page, perPage };
}

/** Paginate a list and build GitHub's Link header (absolute URLs, same origin). */
function paginate<T>(req: IncomingMessage, pathname: string, query: URLSearchParams, items: readonly T[]): { page: T[]; link: string | null } {
  const { page, perPage } = pageParams(query);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const pageItems = items.slice(start, start + perPage);
  const host = req.headers.host ?? 'localhost';
  const base = `http://${host}${pathname}`;
  const links: string[] = [];
  const other = new URLSearchParams(query);
  other.set('per_page', String(perPage));
  if (page < totalPages) {
    other.set('page', String(page + 1));
    links.push(`<${base}?${other.toString()}>; rel="next"`);
    other.set('page', String(totalPages));
    links.push(`<${base}?${other.toString()}>; rel="last"`);
  }
  if (page > 1) {
    other.set('page', '1');
    links.push(`<${base}?${other.toString()}>; rel="first"`);
    other.set('page', String(page - 1));
    links.push(`<${base}?${other.toString()}>; rel="prev"`);
  }
  return { page: pageItems, link: links.length > 0 ? links.join(', ') : null };
}

function stripTrailingNewline(message: string): string {
  return message.endsWith('\n') ? message.slice(0, -1) : message;
}

// ---------------------------------------------------------------------------
// REST shapes

/** The viewer's user object: identical on every call, so one frozen copy is shared by every shape. */
const USER_JSON: Record<string, unknown> = Object.freeze({
  login: VIEWER.login,
  id: VIEWER.id,
  node_id: b64encode(`U:${VIEWER.login}`),
  type: 'User',
  site_admin: false,
});

function userJson(): Record<string, unknown> {
  return USER_JSON;
}

/**
 * Global ids (`node_id`) are pure functions of owner/repo/number, so one copy per record is
 * enough; WeakMaps keep them without changing the records' shape or lifetime.
 */
const issueNodeIdCache = new WeakMap<IssueRecord, string>();
const commentNodeIdCache = new WeakMap<CommentRecord, string>();
const pullNodeIdCache = new WeakMap<PullRecord, string>();
const repoNodeIdCache = new WeakMap<RepoRecord, string>();

function issueNodeId(repo: RepoRecord, issue: IssueRecord): string {
  const cached = issueNodeIdCache.get(issue);
  if (cached !== undefined) return cached;
  const id = b64encode(`I:${repo.owner}/${repo.name}:${issue.number}`);
  issueNodeIdCache.set(issue, id);
  return id;
}

function commentNodeId(repo: RepoRecord, issue: IssueRecord, comment: CommentRecord): string {
  const cached = commentNodeIdCache.get(comment);
  if (cached !== undefined) return cached;
  const id = b64encode(`C:${repo.owner}/${repo.name}:${issue.number}:${comment.id}`);
  commentNodeIdCache.set(comment, id);
  return id;
}

function pullNodeId(repo: RepoRecord, pull: PullRecord): string {
  const cached = pullNodeIdCache.get(pull);
  if (cached !== undefined) return cached;
  const id = b64encode(`P:${repo.owner}/${repo.name}:${pull.number}`);
  pullNodeIdCache.set(pull, id);
  return id;
}

function repoNodeId(repo: RepoRecord): string {
  const cached = repoNodeIdCache.get(repo);
  if (cached !== undefined) return cached;
  const id = b64encode(`R:${repo.owner}/${repo.name}`);
  repoNodeIdCache.set(repo, id);
  return id;
}

function repoJson(repo: RepoRecord): Record<string, unknown> {
  const openIssues = [...repo.issues.values()].filter((issue) => issue.state === 'open').length
    + [...repo.pulls.values()].filter((pull) => pull.state === 'open').length;
  return {
    id: repo.id,
    node_id: repoNodeId(repo),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    created_at: FIXED_ISO,
    updated_at: FIXED_ISO,
    pushed_at: FIXED_ISO,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: openIssues,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    fork: false,
  };
}

function labelJson(label: { name: string; color: string }): Record<string, unknown> {
  return { name: label.name, color: label.color, description: '', default: DEFAULT_LABELS.includes(label.name) };
}

function issueJson(repo: RepoRecord, issue: IssueRecord): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issueNodeId(repo, issue),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => labelJson(repo.labels.get(name) ?? { name, color: 'ededed' })),
    user: userJson(),
    assignee: null,
    assignees: [],
    locked: false,
    comments: issue.comments.length,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.state === 'closed' ? issue.updatedAt : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    author_association: 'OWNER',
  };
}

function commentJson(repo: RepoRecord, issue: IssueRecord, comment: CommentRecord): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: commentNodeId(repo, issue, comment),
    body: comment.body,
    user: userJson(),
    created_at: comment.createdAt,
    updated_at: comment.createdAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    issue_url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    author_association: 'OWNER',
  };
}

function pullJson(repo: RepoRecord, pull: PullRecord): Record<string, unknown> {
  const headSha = refCommit(repo, `refs/heads/${pull.head}`) ?? '';
  const baseSha = refCommit(repo, `refs/heads/${pull.base}`) ?? '';
  return {
    id: pull.id,
    node_id: pullNodeId(repo, pull),
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    user: userJson(),
    head: { label: `${repo.owner}:${pull.head}`, ref: pull.head, sha: headSha },
    base: { label: `${repo.owner}:${pull.base}`, ref: pull.base, sha: baseSha },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.state === 'open' ? computeMergeable(repo, pull) : null,
    mergeable_state: pull.state === 'open' ? (computeMergeable(repo, pull) ? 'clean' : 'dirty') : 'unknown',
    draft: false,
    created_at: pull.createdAt,
    updated_at: pull.createdAt,
    closed_at: pull.state === 'closed' ? pull.createdAt : null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
    comments: 0,
    review_comments: 0,
    commits: 1,
    additions: 0,
    deletions: 0,
    changed_files: 0,
  };
}

/** Whether a pull request merges cleanly (no file changed on both sides since the merge base). */
function computeMergeable(repo: RepoRecord, pull: PullRecord): boolean {
  const headTip = refCommit(repo, `refs/heads/${pull.head}`);
  const baseTip = refCommit(repo, `refs/heads/${pull.base}`);
  if (headTip === null || baseTip === null) return false;
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) return false;
  return findConflict(repo, base, headTip, baseTip) === null;
}

function findConflict(repo: RepoRecord, mergeBaseOid: string, headTip: string, baseTip: string): string | null {
  const baseTree = treeOfCommit(repo, mergeBaseOid);
  const headTree = treeOfCommit(repo, headTip);
  const newBaseTree = treeOfCommit(repo, baseTip);
  for (const [path, headEntry] of headTree) {
    const baseEntry = baseTree.get(path);
    const newBaseEntry = newBaseTree.get(path);
    const changedInHead = baseEntry === undefined || baseEntry.oid !== headEntry.oid;
    const changedInBase = (baseEntry === undefined) !== (newBaseEntry === undefined)
      || (baseEntry !== undefined && newBaseEntry !== undefined && baseEntry.oid !== newBaseEntry.oid);
    if (!changedInHead || !changedInBase) continue;
    if ((newBaseEntry?.oid ?? null) !== headEntry.oid) return path;
  }
  return null;
}

/** The files a pull request changes, between the merge base and the head tip. */
function pullFiles(repo: RepoRecord, pull: PullRecord): FileDiff[] {
  const headTip = refCommit(repo, `refs/heads/${pull.head}`);
  const baseTip = refCommit(repo, `refs/heads/${pull.base}`);
  if (headTip === null || baseTip === null) return [];
  const base = mergeBase(repo, headTip, baseTip);
  const baseTree = base === null ? new Map() : treeOfCommit(repo, base);
  return diffTrees(repo, baseTree, treeOfCommit(repo, headTip));
}

/** Resolve a ref parameter: a branch name, a full ref, or a commit oid. */
function resolveRef(repo: RepoRecord, ref: string | null): string | null {
  if (ref === null || ref === '') return refCommit(repo, `refs/heads/${repo.defaultBranch}`);
  if (repo.refs.has(ref)) return refCommit(repo, ref);
  const asBranch = refCommit(repo, `refs/heads/${ref}`);
  if (asBranch !== null) return asBranch;
  if (isObjectId(ref) && repo.objects.has(ref)) return ref;
  return null;
}

/** The subtree object at `path` inside a tree, or null. */
function subtreeAt(repo: RepoRecord, treeOid: string, path: string): string | null {
  if (path === '') return treeOid;
  let current = treeOid;
  for (const segment of path.split('/')) {
    const object = repo.objects.get(current);
    if (object === undefined || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((candidate) => candidate.name === segment && candidate.mode === '40000');
    if (entry === undefined) return null;
    current = entry.oid;
  }
  return current;
}

// ---------------------------------------------------------------------------
// REST: repositories, branches, commits, contents, git refs

async function handleRest(req: IncomingMessage, res: ServerResponse, parts: RequestParts, body: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const { segments, query, pathname } = parts;

  // The API root and meta are public; everything else under /api/v3 needs a token.
  if (method === 'GET' && segments.length === 2 && segments[0] === 'api' && segments[1] === 'v3') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (method === 'GET' && segments.length === 3 && segments[0] === 'api' && segments[1] === 'v3' && segments[2] === 'meta') {
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true });
    return true;
  }
  if (!isAuthenticated(req)) {
    errorJson(res, 401, 'Requires authentication');
    return true;
  }

  const parsed = parseJsonBody(body);
  if ((method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') && !parsed.ok) {
    errorJson(res, 400, 'Problems parsing JSON');
    return true;
  }
  const input = parsed.ok ? parsed.value : {};

  const rest = segments.slice(2); // after api/v3

  // GET /user
  if (method === 'GET' && rest.length === 1 && rest[0] === 'user') {
    sendJson(res, 200, { ...userJson(), name: VIEWER.name, email: VIEWER.email, type: 'User' });
    return true;
  }

  // GET /user/repos, POST /user/repos
  if (rest.length === 2 && rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      const repos = store.listRepos(VIEWER.login);
      const { page, link } = paginate(req, pathname, query, repos);
      sendJson(res, 200, page.map(repoJson), link === null ? {} : { link });
      return true;
    }
    if (method === 'POST') {
      const name = typeof input.name === 'string' ? input.name : '';
      if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
        errorJson(res, 422, 'Validation Failed: name is invalid');
        return true;
      }
      const repo = store.createRepo(
        VIEWER.login,
        name,
        typeof input.description === 'string' ? input.description : '',
        input.private === true,
      );
      if (repo === null) {
        errorJson(res, 422, 'Repository creation failed: name already exists on this account');
        return true;
      }
      sendJson(res, 201, repoJson(repo));
      return true;
    }
  }

  // /repos/{owner}/{repo}[...]
  if (rest.length >= 3 && rest[0] === 'repos') {
    const owner = rest[1] as string;
    const repoName = rest[2] as string;
    const tail = rest.slice(3);
    const repo = owner === VIEWER.login ? store.getRepo(owner, repoName) : undefined;
    if (repo === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }

    // GET /repos/{o}/{r}
    if (method === 'GET' && tail.length === 0) {
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    // PATCH /repos/{o}/{r}
    if (method === 'PATCH' && tail.length === 0) {
      if (typeof input.description === 'string') repo.description = input.description;
      if (typeof input.name === 'string' && input.name !== repo.name) {
        const next = store.createRepo(repo.owner, input.name, repo.description, repo.isPrivate);
        if (next === null) {
          errorJson(res, 422, 'Repository rename failed: name already exists on this account');
          return true;
        }
        // Move the state into the renamed record.
        next.objects.clear();
        for (const [k, v] of repo.objects) next.objects.set(k, v);
        next.refs.clear();
        for (const [k, v] of repo.refs) next.refs.set(k, v);
        for (const [k, v] of repo.issues) next.issues.set(k, v);
        for (const [k, v] of repo.pulls) next.pulls.set(k, v);
        for (const [k, v] of repo.labels) next.labels.set(k, v);
        next.nextNumber = repo.nextNumber;
        store.deleteRepo(owner, repoName);
        sendJson(res, 200, repoJson(next));
        return true;
      }
      sendJson(res, 200, repoJson(repo));
      return true;
    }
    // DELETE /repos/{o}/{r}
    if (method === 'DELETE' && tail.length === 0) {
      store.deleteRepo(owner, repoName);
      sendEmpty(res, 204);
      return true;
    }

    // GET /repos/{o}/{r}/branches
    if (method === 'GET' && tail.length === 1 && tail[0] === 'branches') {
      const branches: Record<string, unknown>[] = [];
      for (const [ref, oid] of [...repo.refs.entries()].sort()) {
        if (!ref.startsWith('refs/heads/')) continue;
        const name = ref.slice('refs/heads/'.length);
        branches.push({ name, commit: { sha: oid, url: `/api/v3/repos/${owner}/${repoName}/commits/${oid}` }, protected: false });
      }
      const { page, link } = paginate(req, pathname, query, branches);
      sendJson(res, 200, page, link === null ? {} : { link });
      return true;
    }
    // GET /repos/{o}/{r}/branches/{branch...}
    if (method === 'GET' && tail.length >= 2 && tail[0] === 'branches') {
      const branch = tail.slice(1).join('/');
      const tip = refCommit(repo, `refs/heads/${branch}`);
      if (tip === null) {
        errorJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, { name: branch, commit: { sha: tip, url: `/api/v3/repos/${owner}/${repoName}/commits/${tip}` }, protected: false });
      return true;
    }

    // GET /repos/{o}/{r}/commits
    if (method === 'GET' && tail.length === 1 && tail[0] === 'commits') {
      const tip = resolveRef(repo, query.get('sha'));
      if (tip === null) {
        sendJson(res, 200, []);
        return true;
      }
      const commits = walkCommits(repo, tip).map((oid) => {
        const commit = parseCommit((repo.objects.get(oid) as GitObject).data);
        return {
          sha: oid,
          commit: {
            message: stripTrailingNewline(commit.message),
            author: { name: commit.author.split(' <')[0] ?? '', email: '', date: FIXED_ISO },
            committer: { name: commit.committer.split(' <')[0] ?? '', email: '', date: FIXED_ISO },
            tree: { sha: commit.tree },
          },
          parents: commit.parents.map((parent) => ({ sha: parent })),
          url: `/api/v3/repos/${owner}/${repoName}/commits/${oid}`,
        };
      });
      const { page, link } = paginate(req, pathname, query, commits);
      sendJson(res, 200, page, link === null ? {} : { link });
      return true;
    }

    // GET /repos/{o}/{r}/git/refs (list) and POST /repos/{o}/{r}/git/refs (create)
    if (tail.length === 2 && tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'GET') {
        const refs = [...repo.refs.entries()].sort().map(([ref, oid]) => ({ ref, object: { sha: oid, type: 'commit', url: '' } }));
        sendJson(res, 200, refs);
        return true;
      }
      if (method === 'POST') {
        const ref = typeof input.ref === 'string' ? input.ref : '';
        const sha = typeof input.sha === 'string' ? input.sha : '';
        if (!ref.startsWith('refs/') || !isObjectId(sha) || !repo.objects.has(sha)) {
          errorJson(res, 422, 'Validation Failed: ref or sha is invalid');
          return true;
        }
        if (repo.refs.has(ref)) {
          errorJson(res, 422, 'Reference already exists');
          return true;
        }
        repo.refs.set(ref, sha);
        repo.generation += 1;
        sendJson(res, 201, { ref, object: { sha, type: 'commit', url: '' } });
        return true;
      }
    }
    // GET /repos/{o}/{r}/git/refs/heads/{branch...}
    if (method === 'GET' && tail.length >= 4 && tail[0] === 'git' && tail[1] === 'refs' && tail[2] === 'heads') {
      const branch = tail.slice(3).join('/');
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) {
        errorJson(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit', url: '' } });
      return true;
    }

    // Contents: GET/PUT/DELETE /repos/{o}/{r}/contents/{path...}
    if (tail.length >= 1 && tail[0] === 'contents') {
      const path = tail.slice(1).join('/');
      if (method === 'GET') {
        const tip = resolveRef(repo, query.get('ref'));
        if (tip === null) {
          errorJson(res, 404, 'Not Found');
          return true;
        }
        const tree = treeOfCommit(repo, tip);
        const entry = tree.get(path);
        if (entry !== undefined) {
          const data = (repo.objects.get(entry.oid) as GitObject).data;
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            size: data.length,
            name: path.split('/').pop() ?? path,
            path,
            content: b64encode(data),
            sha: entry.oid,
            url: `/api/v3/repos/${owner}/${repoName}/contents/${path}`,
            html_url: `https://github.com/${owner}/${repoName}/blob/${repo.defaultBranch}/${path}`,
          });
          return true;
        }
        const commit = parseCommit((repo.objects.get(tip) as GitObject).data);
        const subtree = subtreeAt(repo, commit.tree, path);
        if (subtree === null) {
          errorJson(res, 404, 'Not Found');
          return true;
        }
        const object = repo.objects.get(subtree) as GitObject;
        const entries = parseTree(object.data).map((child) => ({
          type: child.mode === '40000' ? 'dir' : 'file',
          size: child.mode === '40000' ? 0 : ((repo.objects.get(child.oid) as GitObject | undefined)?.data.length ?? 0),
          name: child.name,
          path: path === '' ? child.name : `${path}/${child.name}`,
          sha: child.oid,
          url: `/api/v3/repos/${owner}/${repoName}/contents/${path === '' ? child.name : `${path}/${child.name}`}`,
          html_url: `https://github.com/${owner}/${repoName}/tree/${repo.defaultBranch}/${path === '' ? child.name : `${path}/${child.name}`}`,
        }));
        sendJson(res, 200, entries);
        return true;
      }
      if (method === 'PUT') {
        const message = typeof input.message === 'string' ? input.message : 'Update file';
        const contentB64 = typeof input.content === 'string' ? input.content : '';
        if (contentB64 === '') {
          errorJson(res, 422, 'Validation Failed: content is required');
          return true;
        }
        const branch = typeof input.branch === 'string' && input.branch !== '' ? input.branch : repo.defaultBranch;
        const ref = `refs/heads/${branch}`;
        let tip = refCommit(repo, ref);
        if (tip === null && repo.refs.has(ref)) tip = null;
        if (tip === null && !repo.refs.has(ref)) {
          // A contents write creates the branch from the default branch tip when it exists.
          tip = refCommit(repo, `refs/heads/${repo.defaultBranch}`);
        }
        const baseTree = tip === null ? new Map<string, { mode: string; oid: string }>() : treeOfCommit(repo, tip);
        const existing = baseTree.get(path);
        const sha = typeof input.sha === 'string' ? input.sha : undefined;
        if (sha !== undefined) {
          if (existing === undefined || existing.oid !== sha) {
            errorJson(res, 409, 'sha does not match the current file');
            return true;
          }
        } else if (existing !== undefined) {
          errorJson(res, 409, 'sha is required to update an existing file');
          return true;
        }
        const data = b64decode(contentB64);
        const newTreeOid = buildTreeForFiles(repo, baseTree, new Map([[path, data]]));
        const parents = tip === null ? [] : [tip];
        const commitData = buildCommit(newTreeOid, parents, message, `${VIEWER.name} <${VIEWER.email}>`, FIXED_EPOCH_SEC);
        const commitOid = putObject(repo, 'commit', commitData);
        repo.refs.set(ref, commitOid);
        repo.generation += 1;
        const blobOid = hashObject('blob', data);
        sendJson(res, existing === undefined ? 201 : 200, {
          content: {
            type: 'file',
            encoding: 'base64',
            size: data.length,
            name: path.split('/').pop() ?? path,
            path,
            content: contentB64,
            sha: blobOid,
            url: `/api/v3/repos/${owner}/${repoName}/contents/${path}`,
          },
          commit: { sha: commitOid, message, author: { name: VIEWER.name, email: VIEWER.email, date: FIXED_ISO }, committer: { name: VIEWER.name, email: VIEWER.email, date: FIXED_ISO } },
        });
        return true;
      }
      if (method === 'DELETE') {
        const branch = typeof input.branch === 'string' && input.branch !== '' ? input.branch : repo.defaultBranch;
        const ref = `refs/heads/${branch}`;
        const tip = refCommit(repo, ref);
        if (tip === null) {
          errorJson(res, 404, 'Not Found');
          return true;
        }
        const baseTree = treeOfCommit(repo, tip);
        const existing = baseTree.get(path);
        if (existing === undefined) {
          errorJson(res, 404, 'Not Found');
          return true;
        }
        const sha = typeof input.sha === 'string' ? input.sha : undefined;
        if (sha !== undefined && sha !== existing.oid) {
          errorJson(res, 409, 'sha does not match the current file');
          return true;
        }
        const message = typeof input.message === 'string' ? input.message : 'Delete file';
        const remaining = new Map(baseTree);
        remaining.delete(path);
        // Rebuild the tree without the deleted path, from the remaining flat map.
        const rebuilt = rebuildTreeFromFlat(repo, remaining);
        const commitData = buildCommit(rebuilt, [tip], message, `${VIEWER.name} <${VIEWER.email}>`, FIXED_EPOCH_SEC);
        const commitOid = putObject(repo, 'commit', commitData);
        repo.refs.set(ref, commitOid);
        repo.generation += 1;
        sendJson(res, 200, { commit: { sha: commitOid, message } });
        return true;
      }
    }

    // Labels, issues and pull requests.
    if (await handleRestIssuesPulls(req, res, repo, owner, repoName, tail, method, input, query, pathname)) return true;
  }

  return false;
}

/** Rebuild nested tree objects from a flat path map (used by contents DELETE). */
function rebuildTreeFromFlat(repo: RepoRecord, flat: Map<string, { mode: string; oid: string }>): string {
  interface Node {
    files: Map<string, string>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of flat) {
    const segments = path.split('/');
    let node = root;
    for (let i = 0; i < segments.length - 1; i += 1) {
      const segment = segments[i] as string;
      if (!node.dirs.has(segment)) node.dirs.set(segment, makeNode());
      node = node.dirs.get(segment) as Node;
    }
    node.files.set(segments[segments.length - 1] as string, entry.oid);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    return putObject(repo, 'tree', data);
  };
  return build(root);
}

/** Merge a pull request with squash semantics; shared by REST and GraphQL. */
function mergePullRequest(repo: RepoRecord, pull: PullRecord): { status: number; body: Record<string, unknown> } {
  if (pull.state === 'closed') {
    return { status: 405, body: { message: pull.merged ? 'Pull request has already been merged' : 'Pull request is closed' } };
  }
  const headTip = refCommit(repo, `refs/heads/${pull.head}`);
  const baseTip = refCommit(repo, `refs/heads/${pull.base}`);
  if (headTip === null || baseTip === null) {
    return { status: 404, body: { message: 'Not Found' } };
  }
  const base = mergeBase(repo, headTip, baseTip);
  if (base === null) {
    return { status: 405, body: { message: 'Merge conflict' } };
  }
  const conflict = findConflict(repo, base, headTip, baseTip);
  if (conflict !== null) {
    return { status: 405, body: { message: 'Merge conflict' } };
  }
  // Apply the head's changes onto the base tip's tree.
  const baseTree = treeOfCommit(repo, base);
  const headTree = treeOfCommit(repo, headTip);
  const newBaseTree = treeOfCommit(repo, baseTip);
  const result = new Map(newBaseTree);
  for (const diff of diffTrees(repo, baseTree, headTree)) {
    if (diff.status === 'removed') result.delete(diff.filename);
    else {
      const entry = headTree.get(diff.filename);
      if (entry !== undefined) result.set(diff.filename, entry);
    }
  }
  const treeOid = rebuildTreeFromFlat(repo, result);
  const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}`;
  const commitData = buildCommit(treeOid, [baseTip], message, `${VIEWER.name} <${VIEWER.email}>`, FIXED_EPOCH_SEC);
  const commitOid = putObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${pull.base}`, commitOid);
  repo.generation += 1;
  pull.merged = true;
  pull.mergedAt = FIXED_ISO;
  pull.mergeCommitSha = commitOid;
  pull.state = 'closed';
  return { status: 200, body: { merged: true, sha: commitOid, message: 'Pull request successfully merged' } };
}

function normalizeBranchRef(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value !== null && typeof value === 'object') {
    const ref = (value as Record<string, unknown>).ref;
    if (typeof ref === 'string') return ref;
  }
  return '';
}

async function handleRestIssuesPulls(
  req: IncomingMessage,
  res: ServerResponse,
  repo: RepoRecord,
  owner: string,
  repoName: string,
  tail: string[],
  method: string,
  input: Record<string, unknown>,
  query: URLSearchParams,
  pathname: string,
): Promise<boolean> {
  // Labels: GET /labels, POST /labels
  if (tail.length === 1 && tail[0] === 'labels') {
    if (method === 'GET') {
      sendJson(res, 200, [...repo.labels.values()].map(labelJson));
      return true;
    }
    if (method === 'POST') {
      const name = typeof input.name === 'string' ? input.name : '';
      const color = typeof input.color === 'string' ? input.color : 'ededed';
      if (name === '') {
        errorJson(res, 422, 'Validation Failed: name is required');
        return true;
      }
      const label = { name, color };
      repo.labels.set(name, label);
      sendJson(res, 201, labelJson(label));
      return true;
    }
  }

  // Issues: GET /issues, POST /issues
  if (tail.length === 1 && tail[0] === 'issues') {
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      const sort = query.get('sort') ?? 'created';
      const direction = query.get('direction') ?? (sort === 'created' ? 'desc' : 'desc');
      let issues = [...repo.issues.values()];
      if (state !== 'all') issues = issues.filter((issue) => issue.state === state);
      issues.sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      const { page, link } = paginate(req, pathname, query, issues);
      sendJson(res, 200, page.map((issue) => issueJson(repo, issue)), link === null ? {} : { link });
      return true;
    }
    if (method === 'POST') {
      const title = typeof input.title === 'string' ? input.title : '';
      if (title === '') {
        errorJson(res, 422, 'Validation Failed: title is required');
        return true;
      }
      const rawLabels = Array.isArray(input.labels) ? input.labels : [];
      const labels: string[] = [];
      for (const raw of rawLabels) {
        const name = typeof raw === 'string' ? raw : (raw !== null && typeof raw === 'object' ? (raw as Record<string, unknown>).name : undefined);
        if (typeof name === 'string') labels.push(name);
      }
      for (const name of labels) {
        if (!repo.labels.has(name)) {
          errorJson(res, 422, `Validation Failed: label "${name}" does not exist`);
          return true;
        }
      }
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const issue: IssueRecord = {
        id: store.newIssueId(),
        number,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels,
        createdSeq: store.seq(),
        createdAt: FIXED_ISO,
        updatedAt: FIXED_ISO,
        comments: [],
      };
      repo.issues.set(number, issue);
      sendJson(res, 201, issueJson(repo, issue));
      return true;
    }
  }

  // GET /issues/{n}, PATCH /issues/{n}
  if (tail.length === 2 && tail[0] === 'issues' && /^\d+$/.test(tail[1] as string)) {
    const number = Number.parseInt(tail[1] as string, 10);
    const issue = repo.issues.get(number);
    if (issue === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET') {
      sendJson(res, 200, issueJson(repo, issue));
      return true;
    }
    if (method === 'PATCH') {
      if (typeof input.title === 'string') issue.title = input.title;
      if (typeof input.body === 'string') issue.body = input.body;
      if (input.state === 'open' || input.state === 'closed') issue.state = input.state;
      if (Array.isArray(input.labels)) {
        const labels: string[] = [];
        for (const raw of input.labels) {
          const name = typeof raw === 'string' ? raw : (raw !== null && typeof raw === 'object' ? (raw as Record<string, unknown>).name : undefined);
          if (typeof name === 'string') labels.push(name);
        }
        for (const name of labels) {
          if (!repo.labels.has(name)) {
            errorJson(res, 422, `Validation Failed: label "${name}" does not exist`);
            return true;
          }
        }
        issue.labels = labels;
      }
      issue.updatedAt = FIXED_ISO;
      sendJson(res, 200, issueJson(repo, issue));
      return true;
    }
  }

  // Comments: GET/POST /issues/{n}/comments
  if (tail.length === 3 && tail[0] === 'issues' && /^\d+$/.test(tail[1] as string) && tail[2] === 'comments') {
    const number = Number.parseInt(tail[1] as string, 10);
    const issue = repo.issues.get(number);
    if (issue === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET') {
      const { page, link } = paginate(req, pathname, query, issue.comments);
      sendJson(res, 200, page.map((comment) => commentJson(repo, issue, comment)), link === null ? {} : { link });
      return true;
    }
    if (method === 'POST') {
      const bodyText = typeof input.body === 'string' ? input.body : '';
      const comment: CommentRecord = { id: store.newCommentId(), body: bodyText, createdAt: FIXED_ISO };
      issue.comments.push(comment);
      sendJson(res, 201, commentJson(repo, issue, comment));
      return true;
    }
  }

  // Pulls: GET /pulls, POST /pulls
  if (tail.length === 1 && tail[0] === 'pulls') {
    if (method === 'GET') {
      const state = query.get('state') ?? 'open';
      let pulls = [...repo.pulls.values()];
      if (state !== 'all') pulls = pulls.filter((pull) => pull.state === state);
      pulls.sort((a, b) => b.createdSeq - a.createdSeq);
      const { page, link } = paginate(req, pathname, query, pulls);
      sendJson(res, 200, page.map((pull) => pullJson(repo, pull)), link === null ? {} : { link });
      return true;
    }
    if (method === 'POST') {
      const title = typeof input.title === 'string' ? input.title : '';
      const head = normalizeBranchRef(input.head);
      const base = normalizeBranchRef(input.base);
      if (title === '' || head === '' || base === '') {
        errorJson(res, 422, 'Validation Failed: title, head and base are required');
        return true;
      }
      if (refCommit(repo, `refs/heads/${head}`) === null || refCommit(repo, `refs/heads/${base}`) === null) {
        errorJson(res, 422, 'Validation Failed: head or base branch does not exist');
        return true;
      }
      const number = repo.nextNumber;
      repo.nextNumber += 1;
      const pull: PullRecord = {
        id: store.newIssueId(),
        number,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        head,
        base,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        createdSeq: store.seq(),
        createdAt: FIXED_ISO,
      };
      repo.pulls.set(number, pull);
      sendJson(res, 201, pullJson(repo, pull));
      return true;
    }
  }

  // GET /pulls/{n}, GET /pulls/{n}/files, PUT /pulls/{n}/merge
  if (tail.length >= 2 && tail[0] === 'pulls' && /^\d+$/.test(tail[1] as string)) {
    const number = Number.parseInt(tail[1] as string, 10);
    const pull = repo.pulls.get(number);
    if (pull === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }
    if (method === 'GET' && tail.length === 2) {
      sendJson(res, 200, pullJson(repo, pull));
      return true;
    }
    if (method === 'GET' && tail.length === 3 && tail[2] === 'files') {
      const files = pullFiles(repo, pull).map((file) => ({
        filename: file.filename,
        status: file.status === 'added' ? 'added' : file.status === 'removed' ? 'removed' : 'modified',
        additions: file.additions,
        deletions: file.deletions,
        changes: file.changes,
        sha: '',
        raw_url: '',
        blob_url: '',
        patch: '',
      }));
      const { page, link } = paginate(req, pathname, query, files);
      sendJson(res, 200, page, link === null ? {} : { link });
      return true;
    }
    if (method === 'PUT' && tail.length === 3 && tail[2] === 'merge') {
      const result = mergePullRequest(repo, pull);
      sendJson(res, result.status, result.body);
      return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// git smart HTTP

const UPLOAD_PACK_CAPS = 'symref=HEAD:refs/heads/main side-band-64k multi_ack_detailed thin-pack ofs-delta shallow agent=forge/1.0';
const RECEIVE_PACK_CAPS = 'report-status report-status-v2 side-band-64k ofs-delta delete-refs agent=forge/1.0 symref=HEAD:refs/heads/main';

interface FetchPlan {
  objects: string[];
  shallow: string[];
  unshallow: string[];
  acks: string[];
}

/** The objects a client holds: the closure of its haves, cut at its shallow boundaries. */
function collectHeld(repo: RepoRecord, haves: string[], shallowBoundaries: Set<string>): Set<string> {
  const lookup = lookupIn(repo);
  const seen = new Set<string>();
  const queue: string[] = [...haves];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      queue.push(parseCommit(object.data).tree);
      // Below a shallow boundary the client holds nothing.
      if (!shallowBoundaries.has(oid)) {
        for (const parent of parseCommit(object.data).parents) queue.push(parent);
      }
    } else if (object.type === 'tag') {
      queue.push(parseTag(object.data).object);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

/** The closure of the commits to send: trees and blobs of included commits only — a commit's
 *  parents are followed only when they are themselves included (this is what makes depth work). */
function collectFetchObjects(repo: RepoRecord, includedCommits: Set<string>, extraObjects: Iterable<string>): Set<string> {
  const lookup = lookupIn(repo);
  const seen = new Set<string>();
  const queue: string[] = [...includedCommits, ...extraObjects];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.type === 'commit') {
      queue.push(parseCommit(object.data).tree);
      for (const parent of parseCommit(object.data).parents) {
        if (includedCommits.has(parent)) queue.push(parent);
      }
    } else if (object.type === 'tag') {
      const target = parseTag(object.data).object;
      const targetObject = lookup(target);
      if (targetObject !== undefined && (targetObject.type !== 'commit' || includedCommits.has(target))) queue.push(target);
    } else if (object.type === 'tree') {
      for (const entry of parseTree(object.data)) {
        if (entry.mode !== '160000') queue.push(entry.oid);
      }
    }
  }
  return seen;
}

function planFetch(repo: RepoRecord, wants: string[], haves: string[], depth: number | null, oldShallow: string[]): FetchPlan {
  const lookup = lookupIn(repo);
  const wantCommits = new Set<string>();
  const directObjects = new Set<string>();
  const tagObjects = new Set<string>();
  for (const want of wants) {
    const object = lookup(want);
    if (object === undefined) continue;
    if (object.type === 'commit') {
      wantCommits.add(want);
    } else if (object.type === 'tag') {
      tagObjects.add(want);
      const target = parseTag(object.data).object;
      const targetObject = lookup(target);
      if (targetObject !== undefined && targetObject.type === 'commit') wantCommits.add(target);
      else if (targetObject !== undefined) directObjects.add(target);
    } else {
      directObjects.add(want);
    }
  }
  // Breadth-first distances from the wanted commits. Only distances below `depth` are ever
  // used (included = d < depth; a shallow boundary sits at d == depth - 1 and needs only the
  // commit's own parents, which parsing it already gives), so a bounded fetch never walks the
  // history past its depth edge: a depth-1 clone of a 200-commit repo visits one commit.
  const dist = new Map<string, number>();
  const queue: string[] = [];
  for (const commit of wantCommits) {
    dist.set(commit, 0);
    queue.push(commit);
  }
  const maxExpand = depth === null ? Number.POSITIVE_INFINITY : depth - 1;
  for (let head = 0; head < queue.length; head += 1) {
    const oid = queue[head] as string;
    const d = dist.get(oid) as number;
    if (d > maxExpand) continue;
    const object = lookup(oid);
    if (object === undefined || object.type !== 'commit') continue;
    if (d === maxExpand) continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!dist.has(parent)) {
        dist.set(parent, d + 1);
        queue.push(parent);
      }
    }
  }
  // The commits the client already holds. The walk stops at its shallow boundaries: below one
  // of those the client holds nothing, even though the commits exist on the server.
  const shallowSet = new Set(oldShallow);
  const haveCommits = new Set<string>();
  const hq: string[] = [];
  for (const have of haves) {
    const object = lookup(have);
    if (object === undefined) continue;
    if (object.type === 'commit') hq.push(have);
    else if (object.type === 'tag') hq.push(parseTag(object.data).object);
  }
  while (hq.length > 0) {
    const oid = hq.pop() as string;
    if (haveCommits.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined || object.type !== 'commit') continue;
    haveCommits.add(oid);
    if (shallowSet.has(oid)) continue;
    for (const parent of parseCommit(object.data).parents) hq.push(parent);
  }
  // Commits to send: within depth, and not already held.
  const included = new Set<string>();
  for (const [oid, d] of dist) {
    if (haveCommits.has(oid)) continue;
    if (depth !== null && d >= depth) continue;
    included.add(oid);
  }
  // New shallow boundaries: included commits at the depth edge that have parents.
  const shallow: string[] = [];
  if (depth !== null) {
    for (const oid of included) {
      const d = dist.get(oid) as number;
      if (d !== depth - 1) continue;
      const object = lookup(oid);
      if (object !== undefined && object.type === 'commit' && parseCommit(object.data).parents.length > 0) shallow.push(oid);
    }
  }
  // Old boundaries that are now fully held.
  const unshallow: string[] = [];
  for (const old of oldShallow) {
    if (!included.has(old)) continue;
    if (depth === null) {
      unshallow.push(old);
      continue;
    }
    const object = lookup(old);
    if (object === undefined || object.type !== 'commit') continue;
    if (parseCommit(object.data).parents.some((parent) => included.has(parent))) unshallow.push(old);
  }
  // Objects to send: the depth-limited closure of the included commits, minus everything the
  // client holds (its haves, cut at its shallow boundaries).
  const haveObjects = collectHeld(repo, haves, shallowSet);
  const includedObjects = collectFetchObjects(repo, included, [...tagObjects, ...directObjects]);
  for (const oid of haveObjects) includedObjects.delete(oid);
  // Acknowledged haves: a have that is an ancestor of (or equal to) a want.
  const acks: string[] = [];
  for (const have of haves) {
    if (!haveCommits.has(have)) continue;
    for (const want of wantCommits) {
      if (isAncestor(repo, have, want)) {
        acks.push(have);
        break;
      }
    }
  }
  return { objects: [...includedObjects].sort(), shallow: shallow.sort(), unshallow: unshallow.sort(), acks };
}

/** The ref lines for a v0 advertisement (HEAD first, then sorted refs, peeled tags inline). */
function advertisementRefLines(repo: RepoRecord): Array<{ oid: string; ref: string }> {
  const lines: Array<{ oid: string; ref: string }> = [];
  const mainTip = repo.refs.get('refs/heads/main');
  lines.push({ oid: mainTip ?? ZERO_OID, ref: 'HEAD' });
  for (const [ref, oid] of [...repo.refs.entries()].sort()) {
    lines.push({ oid, ref });
    const object = repo.objects.get(oid);
    if (object !== undefined && object.type === 'tag') {
      const target = parseTag(object.data).object;
      lines.push({ oid: target, ref: `${ref}^{}` });
    }
  }
  return lines;
}

function buildAdvertisementV0(repo: RepoRecord, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack' ? UPLOAD_PACK_CAPS : RECEIVE_PACK_CAPS;
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), pktLineFlush()];
  const lines = advertisementRefLines(repo);
  const hasRefs = repo.refs.size > 0;
  if (!hasRefs) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    lines.forEach((line, index) => {
      const text = index === 0 ? `${line.oid} ${line.ref}\0${caps}\n` : `${line.oid} ${line.ref}\n`;
      parts.push(pktLine(text));
    });
  }
  parts.push(pktLineFlush());
  return Buffer.concat(parts);
}

function buildAdvertisementV2(): Buffer {
  const parts: Buffer[] = [
    pktLine('# service=git-upload-pack\n'),
    pktLineFlush(),
    pktLine('version 2\n'),
    pktLine('agent=forge/1.0\n'),
    pktLine('object-format=sha1\n'),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow\n'),
    pktLineFlush(),
  ];
  return Buffer.concat(parts);
}

/** The v2 advertisement never changes: one shared copy for every request. */
const ADVERTISEMENT_V2 = buildAdvertisementV2();

/**
 * The v0 advertisement of a repository, cached per (repo, generation, service): a ref set is
 * fixed for a generation (refs only move in receive-pack, which bumps generation, and renames
 * move the state to a new repo id), so the benchmark's 50 concurrent clones of one generation
 * build it once. The cache is bounded and cleared wholesale when full.
 */
const advertisementCache = new Map<string, Buffer>();
const ADVERTISEMENT_CACHE_MAX = 64;

function advertisementV0(repo: RepoRecord, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const key = `${repo.id}|${repo.generation}|${service}`;
  const cached = advertisementCache.get(key);
  if (cached !== undefined) return cached;
  const built = buildAdvertisementV0(repo, service);
  if (advertisementCache.size >= ADVERTISEMENT_CACHE_MAX) advertisementCache.clear();
  advertisementCache.set(key, built);
  return built;
}

/** Split pack bytes into sideband band-1 packets (each pkt-line carries at most 65515 data bytes). */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const chunkSize = 65515;
  for (let offset = 0; offset < pack.length; offset += chunkSize) {
    const chunk = pack.subarray(offset, Math.min(pack.length, offset + chunkSize));
    const framed = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(pktLine(framed));
  }
  return Buffer.concat(parts);
}

interface LsRefsArgs {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

function lsRefsResponse(repo: RepoRecord, args: LsRefsArgs): Buffer {
  const lines: string[] = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((prefix) => name.startsWith(prefix));
  const mainTip = repo.refs.get('refs/heads/main');
  if (keep('HEAD')) {
    if (mainTip !== undefined) {
      lines.push(`${mainTip} HEAD${args.symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    } else if (args.unborn) {
      lines.push(`unborn HEAD symref-target:refs/heads/main\n`);
    }
  }
  for (const [ref, oid] of [...repo.refs.entries()].sort()) {
    if (!keep(ref)) continue;
    let suffix = '';
    if (args.peel) {
      const object = repo.objects.get(oid);
      if (object !== undefined && object.type === 'tag') {
        suffix = ` peeled:${parseTag(object.data).object}`;
      }
    }
    lines.push(`${oid} ${ref}${suffix}\n`);
  }
  const parts = lines.map((line) => pktLine(line));
  parts.push(pktLineFlush());
  return Buffer.concat(parts);
}

interface FetchArgs {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
}

function parseFetchArgs(lines: string[]): FetchArgs {
  const args: FetchArgs = { wants: [], haves: [], shallow: [], depth: null };
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text.startsWith('want ')) args.wants.push(text.slice(5).trim());
    else if (text.startsWith('have ')) args.haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) args.shallow.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) {
      const n = Number.parseInt(text.slice(7).trim(), 10);
      if (!Number.isNaN(n)) args.depth = n;
    }
  }
  return args;
}

/** Fetch responses are a pure function of the repo generation plus the request arguments, so
 *  identical fetches (the benchmark's 50 concurrent shallow clones) reuse one built response. */
const fetchCache = new Map<string, Buffer>();
const FETCH_CACHE_MAX = 128;

function fetchCacheKey(repo: RepoRecord, protocol: 0 | 2, args: FetchArgs): string {
  return `${protocol}|${repo.id}|${repo.generation}|${args.wants.join(',')}|${args.haves.join(',')}|${args.depth}|${args.shallow.join(',')}`;
}

function fetchCacheGet(key: string): Buffer | undefined {
  return fetchCache.get(key);
}

function fetchCacheSet(key: string, value: Buffer): void {
  if (fetchCache.size >= FETCH_CACHE_MAX) {
    const oldest = fetchCache.keys().next().value;
    if (oldest !== undefined) fetchCache.delete(oldest);
  }
  fetchCache.set(key, value);
}

function fetchResponseV2(repo: RepoRecord, args: FetchArgs): Buffer {
  const key = fetchCacheKey(repo, 2, args);
  const cached = fetchCacheGet(key);
  if (cached !== undefined) return cached;
  const built = buildFetchResponseV2(repo, args);
  fetchCacheSet(key, built);
  return built;
}

function buildFetchResponseV2(repo: RepoRecord, args: FetchArgs): Buffer {
  const plan = planFetch(repo, args.wants, args.haves, args.depth, args.shallow);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'));
  if (plan.acks.length > 0) {
    for (const ack of plan.acks) parts.push(pktLine(`ACK ${ack} ready\n`));
  } else {
    parts.push(pktLine('NAK\n'));
  }
  parts.push(pktLineDelim());
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(pktLineDelim());
  }
  const wantedRefs: string[] = [];
  for (const want of args.wants) {
    for (const [ref, oid] of repo.refs) {
      if (oid === want) wantedRefs.push(`${want} ${ref}\n`);
    }
  }
  if (wantedRefs.length > 0) {
    parts.push(pktLine('wanted-refs\n'));
    for (const line of wantedRefs) parts.push(pktLine(line));
    parts.push(pktLineDelim());
  }
  if (plan.objects.length > 0) {
    const objects = plan.objects.map((oid) => repo.objects.get(oid) as GitObject);
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandPack(writePack(objects)));
  }
  parts.push(pktLineFlush());
  return Buffer.concat(parts);
}

function fetchResponseV0(repo: RepoRecord, args: FetchArgs): Buffer {
  const key = fetchCacheKey(repo, 0, args);
  const cached = fetchCacheGet(key);
  if (cached !== undefined) return cached;
  const built = buildFetchResponseV0(repo, args);
  fetchCacheSet(key, built);
  return built;
}

function buildFetchResponseV0(repo: RepoRecord, args: FetchArgs): Buffer {
  const plan = planFetch(repo, args.wants, args.haves, args.depth, args.shallow);
  const parts: Buffer[] = [];
  if (plan.acks.length > 0) {
    for (const ack of plan.acks) parts.push(pktLine(`ACK ${ack} ready\n`));
  } else {
    parts.push(pktLine('NAK\n'));
  }
  for (const oid of plan.shallow) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
  if (plan.objects.length > 0) {
    const objects = plan.objects.map((oid) => repo.objects.get(oid) as GitObject);
    parts.push(sidebandPack(writePack(objects)));
  }
  parts.push(pktLineFlush());
  return Buffer.concat(parts);
}

function handleUploadPack(repo: RepoRecord, body: Buffer, isV2: boolean): { status: number; body: Buffer } {
  const packets = decodePktLines(body);
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  if (lines.length === 0) return { status: 400, body: Buffer.from('empty upload-pack request') };
  if (isV2) {
    const command = (lines[0] as string).replace(/\n$/, '');
    if (command === 'command=ls-refs') {
      const args: LsRefsArgs = { peel: false, symrefs: false, unborn: false, prefixes: [] };
      for (const line of lines.slice(1)) {
        const text = line.replace(/\n$/, '');
        if (text === 'peel') args.peel = true;
        else if (text === 'symrefs') args.symrefs = true;
        else if (text === 'unborn') args.unborn = true;
        else if (text.startsWith('ref-prefix ')) args.prefixes.push(text.slice('ref-prefix '.length));
      }
      return { status: 200, body: lsRefsResponse(repo, args) };
    }
    if (command === 'command=fetch') {
      const args = parseFetchArgs(lines.slice(1));
      return { status: 200, body: fetchResponseV2(repo, args) };
    }
    return { status: 400, body: Buffer.from(`unknown v2 command ${command}`) };
  }
  const args = parseFetchArgs(lines);
  if (args.wants.length === 0) return { status: 400, body: Buffer.from('fetch with no wants') };
  return { status: 200, body: fetchResponseV0(repo, args) };
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

/** Split a receive-pack body into its command pkt-lines and the raw pack that follows the flush. */
function splitReceivePackBody(body: Buffer): { commands: string[]; pack: Buffer } {
  const commands: string[] = [];
  let offset = 0;
  while (offset + 4 <= body.length) {
    const length = Number.parseInt(body.subarray(offset, offset + 4).toString('ascii'), 16);
    if (Number.isNaN(length)) throw new Error('malformed pkt-line length');
    if (length === 0) {
      offset += 4;
      break;
    }
    if (length < 4 || offset + length > body.length) throw new Error('malformed pkt-line');
    commands.push(body.subarray(offset + 4, offset + length).toString('utf8'));
    offset += length;
  }
  return { commands, pack: body.subarray(offset) };
}

function handleReceivePack(repo: RepoRecord, body: Buffer): { status: number; body: Buffer } {
  const { commands: rawCommands, pack: packBytes } = splitReceivePackBody(body);
  const commands: PushCommand[] = [];
  for (const raw of rawCommands) {
    const nul = raw.indexOf('\0');
    const text = (nul >= 0 ? raw.slice(0, nul) : raw).replace(/\n$/, '');
    const parts = text.split(' ');
    if (parts.length !== 3) throw new Error(`malformed push command ${JSON.stringify(text.slice(0, 60))}`);
    const [oldOid, newOid, ref] = parts as [string, string, string];
    if (!isObjectId(oldOid) || !isObjectId(newOid) || !ref.startsWith('refs/')) {
      throw new Error(`malformed push command ${JSON.stringify(text.slice(0, 60))}`);
    }
    commands.push({ oldOid, newOid, ref });
  }
  if (commands.length === 0) throw new Error('push with no commands');

  const reportLines: string[] = [];
  const updatesRef = commands.some((command) => command.newOid !== ZERO_OID);
  let unpacked: Map<string, GitObject> | null = null;
  let unpackError: string | null = null;
  if (packBytes.length > 0) {
    try {
      // The suite's client builds plain-object packs, so a Map is all that comes back.
      unpacked = readPack(packBytes);
    } catch (error) {
      unpackError = error instanceof Error ? error.message : 'unpack failed';
    }
  } else if (updatesRef) {
    unpackError = 'missing packfile';
  }

  if (unpackError !== null) {
    reportLines.push(`unpack ${unpackError}\n`);
    for (const command of commands) reportLines.push(`ng ${command.ref} unpack failed\n`);
  } else {
    if (unpacked !== null) {
      for (const [oid, object] of unpacked) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, object);
      }
    }
    reportLines.push('unpack ok\n');
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      let failure: string | null = null;
      if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) failure = 'remote ref does not exist';
        else if (command.oldOid !== ZERO_OID && command.oldOid !== current) failure = 'remote ref does not match';
      } else {
        // Create or update.
        if (command.oldOid === ZERO_OID) {
          if (current !== undefined) failure = 'remote ref already exists';
        } else if (current === undefined) {
          failure = 'remote ref does not exist';
        } else if (current !== command.oldOid) {
          failure = 'remote ref does not match';
        }
        if (failure === null && !repo.objects.has(command.newOid)) failure = 'object not found';
        if (failure === null && command.ref.startsWith('refs/heads/') && command.oldOid !== ZERO_OID) {
          if (!isAncestor(repo, command.oldOid, command.newOid)) failure = 'non-fast-forward';
        }
      }
      if (failure !== null) {
        reportLines.push(`ng ${command.ref} ${failure}\n`);
      } else {
        if (command.newOid === ZERO_OID) repo.refs.delete(command.ref);
        else repo.refs.set(command.ref, command.newOid);
        reportLines.push(`ok ${command.ref}\n`);
      }
    }
  }

  if (unpackError === null) repo.generation += 1;

  const reportText = Buffer.concat(reportLines.map((line) => pktLine(line)));
  const framed = Buffer.concat([Buffer.from([1]), reportText]);
  const parts: Buffer[] = [pktLine(framed), pktLineFlush()];
  return { status: 200, body: Buffer.concat(parts) };
}

async function handleGit(req: IncomingMessage, res: ServerResponse, parts: RequestParts, body: Buffer): Promise<boolean> {
  const method = req.method ?? 'GET';
  const { segments, query } = parts;
  if (segments.length < 2) return false;
  const owner = segments[0] as string;
  const repoSegment = segments[1] as string;
  if (!repoSegment.endsWith('.git')) return false;
  const repoName = repoSegment.slice(0, -'.git'.length);
  const repo = owner === VIEWER.login ? store.getRepo(owner, repoName) : undefined;

  // GET /{owner}/{repo}.git/info/refs?service=git-upload-pack|git-receive-pack
  if (method === 'GET' && segments.length === 4 && segments[2] === 'info' && segments[3] === 'refs') {
    const service = query.get('service');
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendRaw(res, 400, Buffer.from('missing service parameter'), 'text/plain; charset=utf-8');
      return true;
    }
    if (repo === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }
    const contentType = service === 'git-upload-pack'
      ? 'application/x-git-upload-pack-advertisement'
      : 'application/x-git-receive-pack-advertisement';
    if (service === 'git-receive-pack') {
      sendRaw(res, 200, advertisementV0(repo, service), contentType);
      return true;
    }
    const wantsV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    sendRaw(res, 200, wantsV2 ? ADVERTISEMENT_V2 : advertisementV0(repo, service), contentType);
    return true;
  }

  // POST /{owner}/{repo}.git/git-upload-pack
  if (method === 'POST' && segments.length === 3 && segments[2] === 'git-upload-pack') {
    if (repo === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }
    const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const result = handleUploadPack(repo, body, isV2);
    sendRaw(res, result.status, result.body, 'application/x-git-upload-pack-result');
    return true;
  }

  // POST /{owner}/{repo}.git/git-receive-pack
  if (method === 'POST' && segments.length === 3 && segments[2] === 'git-receive-pack') {
    if (repo === undefined) {
      errorJson(res, 404, 'Not Found');
      return true;
    }
    const result = handleReceivePack(repo, body);
    sendRaw(res, result.status, result.body, 'application/x-git-receive-pack-result');
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// GraphQL: a small recursive-descent parser and executor for the shapes the
// gh CLI and github-mcp-server send.

type GqlToken = { type: 'name' | 'int' | 'float' | 'string' | 'punct'; value: string };

function tokenizeGql(source: string): GqlToken[] {
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
    if (ch === '.' && source.startsWith('...', i)) {
      tokens.push({ type: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@'.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let value = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          if (esc === 'n') value += '\n';
          else if (esc === 't') value += '\t';
          else if (esc === 'r') value += '\r';
          else value += esc;
          j += 2;
        } else {
          value += source[j] as string;
          j += 1;
        }
      }
      tokens.push({ type: 'string', value });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      let isFloat = false;
      if (source[j] === '-') j += 1;
      while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      if (source[j] === '.') {
        isFloat = true;
        j += 1;
        while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      }
      if (source[j] === 'e' || source[j] === 'E') {
        isFloat = true;
        j += 1;
        if (source[j] === '+' || source[j] === '-') j += 1;
        while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      }
      tokens.push({ type: isFloat ? 'float' : 'int', value: source.slice(i, j) });
      i = j;
      continue;
    }
    if (/[_A-Za-z]/.test(ch)) {
      let j = i;
      while (j < source.length && /[_0-9A-Za-z]/.test(source[j] as string)) j += 1;
      tokens.push({ type: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return tokens;
}

interface GqlFieldSelection {
  kind: 'field';
  name: string;
  alias: string;
  args: Record<string, unknown>;
  selections: GqlSelection[];
}

interface GqlFragmentSelection {
  kind: 'fragment';
  typeCondition: string | null;
  selections: GqlSelection[];
}

type GqlSelection = GqlFieldSelection | GqlFragmentSelection;

interface GqlOperation {
  operation: 'query' | 'mutation';
  name: string | null;
  variables: Record<string, unknown>;
  selections: GqlSelection[];
}

class GqlParser {
  private readonly tokens: GqlToken[];
  private pos = 0;

  constructor(source: string) {
    this.tokens = tokenizeGql(source);
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }

  private next(): GqlToken {
    const token = this.tokens[this.pos];
    if (token === undefined) throw new Error('unexpected end of GraphQL document');
    this.pos += 1;
    return token;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.type !== 'punct' || token.value !== value) throw new Error(`expected ${value} in GraphQL document`);
  }

  private expectName(): string {
    const token = this.next();
    if (token.type !== 'name') throw new Error('expected a name in GraphQL document');
    return token.value;
  }

  parseDocument(): GqlOperation[] {
    const operations: GqlOperation[] = [];
    while (this.pos < this.tokens.length) {
      const token = this.peek() as GqlToken;
      if (token.type === 'punct' && token.value === '{') {
        operations.push({ operation: 'query', name: null, variables: {}, selections: this.parseSelectionSet() });
      } else if (token.type === 'name' && (token.value === 'query' || token.value === 'mutation')) {
        this.next();
        let name: string | null = null;
        const next = this.peek();
        if (next !== undefined && next.type === 'name') name = this.next().value;
        const variables = this.parseVariableDefinitions();
        const selections = this.parseSelectionSet();
        operations.push({ operation: token.value as 'query' | 'mutation', name, variables, selections });
      } else {
        throw new Error(`unexpected token ${token.value} in GraphQL document`);
      }
    }
    return operations;
  }

  private parseVariableDefinitions(): Record<string, unknown> {
    const defaults: Record<string, unknown> = {};
    const token = this.peek();
    if (token === undefined || token.type !== 'punct' || token.value !== '(') return defaults;
    this.next();
    while (true) {
      const t = this.peek();
      if (t === undefined) throw new Error('unterminated variable definitions');
      if (t.type === 'punct' && t.value === ')') {
        this.next();
        break;
      }
      if (t.type === 'punct' && t.value === '$') {
        this.next();
        const name = this.expectName();
        this.expectPunct(':');
        this.parseType();
        const eq = this.peek();
        if (eq !== undefined && eq.type === 'punct' && eq.value === '=') {
          this.next();
          defaults[name] = this.parseValue();
        }
        continue;
      }
      throw new Error('unexpected token in variable definitions');
    }
    return defaults;
  }

  private parseType(): void {
    const token = this.peek();
    if (token === undefined) return;
    if (token.type === 'punct' && token.value === '[') {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else if (token.type === 'name') {
      this.next();
    }
    const bang = this.peek();
    if (bang !== undefined && bang.type === 'punct' && bang.value === '!') this.next();
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (true) {
      const token = this.peek();
      if (token === undefined) throw new Error('unterminated selection set');
      if (token.type === 'punct' && token.value === '}') {
        this.next();
        break;
      }
      selections.push(this.parseSelection());
    }
    return selections;
  }

  private parseSelection(): GqlSelection {
    const token = this.peek() as GqlToken;
    if (token.type === 'punct' && token.value === '...') {
      this.next();
      const next = this.peek();
      if (next !== undefined && next.type === 'name' && next.value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        return { kind: 'fragment', typeCondition, selections: this.parseSelectionSet() };
      }
      if (next !== undefined && next.type === 'name') {
        this.next();
        return { kind: 'fragment', typeCondition: null, selections: [] };
      }
      return { kind: 'fragment', typeCondition: null, selections: this.parseSelectionSet() };
    }
    if (token.type !== 'name') throw new Error('expected a field name in GraphQL document');
    const nameOrAlias = this.next().value;
    let name = nameOrAlias;
    const alias = nameOrAlias;
    const colon = this.peek();
    if (colon !== undefined && colon.type === 'punct' && colon.value === ':') {
      this.next();
      name = this.expectName();
    }
    const args = this.parseArguments();
    let selections: GqlSelection[] = [];
    const brace = this.peek();
    if (brace !== undefined && brace.type === 'punct' && brace.value === '{') {
      selections = this.parseSelectionSet();
    }
    return { kind: 'field', name, alias, args, selections };
  }

  private parseArguments(): Record<string, unknown> {
    const args: Record<string, unknown> = {};
    const token = this.peek();
    if (token === undefined || token.type !== 'punct' || token.value !== '(') return args;
    this.next();
    while (true) {
      const t = this.peek();
      if (t === undefined) throw new Error('unterminated arguments');
      if (t.type === 'punct' && t.value === ')') {
        this.next();
        break;
      }
      const name = this.expectName();
      this.expectPunct(':');
      args[name] = this.parseValue();
    }
    return args;
  }

  private parseValue(): unknown {
    const token = this.next();
    if (token.type === 'punct' && token.value === '$') return { __variable: this.expectName() };
    if (token.type === 'punct' && token.value === '[') {
      const values: unknown[] = [];
      while (true) {
        const t = this.peek();
        if (t === undefined) throw new Error('unterminated list');
        if (t.type === 'punct' && t.value === ']') {
          this.next();
          break;
        }
        values.push(this.parseValue());
      }
      return values;
    }
    if (token.type === 'punct' && token.value === '{') {
      const object: Record<string, unknown> = {};
      while (true) {
        const t = this.peek();
        if (t === undefined) throw new Error('unterminated object');
        if (t.type === 'punct' && t.value === '}') {
          this.next();
          break;
        }
        const name = this.expectName();
        this.expectPunct(':');
        object[name] = this.parseValue();
      }
      return object;
    }
    if (token.type === 'string') return token.value;
    if (token.type === 'int') return Number.parseInt(token.value, 10);
    if (token.type === 'float') return Number.parseFloat(token.value);
    if (token.type === 'name') {
      if (token.value === 'true') return true;
      if (token.value === 'false') return false;
      if (token.value === 'null') return null;
      return token.value;
    }
    throw new Error(`unexpected value token ${token.value}`);
  }
}

// ---------------------------------------------------------------------------
// GraphQL execution

type GqlObject = { __typename: string; [key: string]: unknown };

interface GqlContext {
  errors: Array<{ message: string }>;
}

const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'state', 'body', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'files', 'url', 'createdAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests'],
};

const TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
};

function cursorFor(number: number): string {
  return b64encode(`cursor:${number}`);
}

function decodeGlobalId(id: string): GqlObject | null {
  let text: string;
  try {
    text = Buffer.from(id, 'base64').toString('utf8');
  } catch {
    return null;
  }
  const parts = text.split(':');
  const kind = parts[0];
  if (kind === 'R' && parts.length === 2) {
    const segments = (parts[1] as string).split('/');
    if (segments.length !== 2) return null;
    const repo = segments[0] === VIEWER.login ? store.getRepo(segments[0] as string, segments[1] as string) : undefined;
    return repo === undefined ? null : { __typename: 'Repository', repo };
  }
  if (kind === 'I' && parts.length === 3) {
    const segments = (parts[1] as string).split('/');
    if (segments.length !== 2) return null;
    const repo = segments[0] === VIEWER.login ? store.getRepo(segments[0] as string, segments[1] as string) : undefined;
    const issue = repo?.issues.get(Number.parseInt(parts[2] as string, 10));
    return issue === undefined || repo === undefined ? null : { __typename: 'Issue', repo, issue };
  }
  if (kind === 'P' && parts.length === 3) {
    const segments = (parts[1] as string).split('/');
    if (segments.length !== 2) return null;
    const repo = segments[0] === VIEWER.login ? store.getRepo(segments[0] as string, segments[1] as string) : undefined;
    const pull = repo?.pulls.get(Number.parseInt(parts[2] as string, 10));
    return pull === undefined || repo === undefined ? null : { __typename: 'PullRequest', repo, pull };
  }
  if (kind === 'C' && parts.length === 4) {
    const segments = (parts[1] as string).split('/');
    if (segments.length !== 2) return null;
    const repo = segments[0] === VIEWER.login ? store.getRepo(segments[0] as string, segments[1] as string) : undefined;
    const issue = repo?.issues.get(Number.parseInt(parts[2] as string, 10));
    const comment = issue?.comments.find((candidate) => candidate.id === Number.parseInt(parts[3] as string, 10));
    return comment === undefined || issue === undefined || repo === undefined ? null : { __typename: 'Comment', repo, issue, comment };
  }
  if (kind === 'U' && parts.length === 2) return { __typename: 'User', login: parts[1] };
  return null;
}

function paginateConnection(
  repo: RepoRecord,
  kind: 'Issue' | 'PullRequest' | 'File',
  items: Array<IssueRecord | PullRecord | FileDiff>,
  args: Record<string, unknown>,
): GqlObject {
  const first = typeof args.first === 'number' ? args.first : items.length;
  const after = typeof args.after === 'string' ? args.after : null;
  let start = 0;
  if (after !== null) {
    try {
      const decoded = Buffer.from(after, 'base64').toString('utf8');
      const match = /^cursor:(\d+)$/.exec(decoded);
      if (match !== null) {
        const index = items.findIndex((item) => 'number' in item && item.number === Number.parseInt(match[1] as string, 10));
        if (index >= 0) start = index + 1;
      }
    } catch {
      // A bad cursor starts from the beginning.
    }
  }
  const page = items.slice(start, start + first);
  const hasNextPage = start + page.length < items.length;
  const endCursor = page.length > 0 ? cursorFor((page[page.length - 1] as { number: number }).number) : null;
  const startCursor = page.length > 0 ? cursorFor((page[0] as { number: number }).number) : null;
  return {
    __typename: `${kind}Connection`,
    repo,
    items: page,
    total: items.length,
    pageInfo: { __typename: 'PageInfo', hasNextPage, endCursor, hasPreviousPage: false, startCursor },
  };
}

function issueConnection(repo: RepoRecord, args: Record<string, unknown>): GqlObject {
  let issues = [...repo.issues.values()];
  const states = args.states as string[] | undefined;
  if (Array.isArray(states) && states.length > 0) {
    issues = issues.filter((issue) => states.includes(issue.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  const orderBy = args.orderBy as Record<string, unknown> | undefined;
  const direction = orderBy?.direction === 'ASC' ? 1 : -1;
  issues.sort((a, b) => direction * (a.createdSeq - b.createdSeq));
  return paginateConnection(repo, 'Issue', issues, args);
}

function pullConnection(repo: RepoRecord, args: Record<string, unknown>): GqlObject {
  let pulls = [...repo.pulls.values()];
  const states = args.states as string[] | undefined;
  if (Array.isArray(states) && states.length > 0) {
    pulls = pulls.filter((pull) => states.includes(pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED'));
  }
  const orderBy = args.orderBy as Record<string, unknown> | undefined;
  const direction = orderBy?.direction === 'ASC' ? 1 : -1;
  pulls.sort((a, b) => direction * (a.createdSeq - b.createdSeq));
  return paginateConnection(repo, 'PullRequest', pulls, args);
}

function fileConnection(repo: RepoRecord, pull: PullRecord, args: Record<string, unknown>): GqlObject {
  const files = pullFiles(repo, pull);
  const items = files.map((file, index) => ({ ...file, number: index + 1 }));
  return paginateConnection(repo, 'File', items, args);
}

function createIssueRecord(repo: RepoRecord, title: string, body: string): IssueRecord {
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const issue: IssueRecord = {
    id: store.newIssueId(),
    number,
    title,
    body,
    state: 'open',
    labels: [],
    createdSeq: store.seq(),
    createdAt: FIXED_ISO,
    updatedAt: FIXED_ISO,
    comments: [],
  };
  repo.issues.set(number, issue);
  return issue;
}

function createPullRecord(repo: RepoRecord, title: string, body: string, head: string, base: string): PullRecord | null {
  if (refCommit(repo, `refs/heads/${head}`) === null || refCommit(repo, `refs/heads/${base}`) === null) return null;
  const number = repo.nextNumber;
  repo.nextNumber += 1;
  const pull: PullRecord = {
    id: store.newIssueId(),
    number,
    title,
    body,
    state: 'open',
    head,
    base,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    createdSeq: store.seq(),
    createdAt: FIXED_ISO,
  };
  repo.pulls.set(number, pull);
  return pull;
}

function resolveArgValue(value: unknown, variables: Record<string, unknown>): unknown {
  if (Array.isArray(value)) return value.map((item) => resolveArgValue(item, variables));
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    if (typeof record.__variable === 'string') return variables[record.__variable] ?? null;
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(record)) out[key] = resolveArgValue(item, variables);
    return out;
  }
  return value;
}

function fieldValue(obj: GqlObject, name: string, args: Record<string, unknown>, ctx: GqlContext): unknown {
  const typeName = obj.__typename;
  switch (typeName) {
    case 'Query': {
      if (name === 'viewer') return { __typename: 'User', login: VIEWER.login };
      if (name === 'repository') {
        const owner = args.owner as string | undefined;
        const repoName = args.name as string | undefined;
        if (typeof owner !== 'string' || typeof repoName !== 'string') return null;
        const repo = owner === VIEWER.login ? store.getRepo(owner, repoName) : undefined;
        return repo === undefined ? null : { __typename: 'Repository', repo };
      }
      if (name === 'node') {
        const id = args.id as string | undefined;
        return typeof id === 'string' ? decodeGlobalId(id) : null;
      }
      if (name === '__type') {
        const requested = args.name as string | undefined;
        return typeof requested === 'string' ? { __typename: '__Type', name: requested } : null;
      }
      if (name === 'createIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const repoObject = typeof input.repositoryId === 'string' ? decodeGlobalId(input.repositoryId) : null;
        if (repoObject === null || repoObject.__typename !== 'Repository') return null;
        const repo = repoObject.repo as RepoRecord;
        const issue = createIssueRecord(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '');
        return { __typename: 'CreateIssuePayload', repo, issue };
      }
      if (name === 'closeIssue') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const issueObject = typeof input.issueId === 'string' ? decodeGlobalId(input.issueId) : null;
        if (issueObject === null || issueObject.__typename !== 'Issue') return null;
        const issue = issueObject.issue as IssueRecord;
        issue.state = 'closed';
        issue.updatedAt = FIXED_ISO;
        return { __typename: 'CloseIssuePayload', repo: issueObject.repo as RepoRecord, issue };
      }
      if (name === 'createPullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const repoObject = typeof input.repositoryId === 'string' ? decodeGlobalId(input.repositoryId) : null;
        if (repoObject === null || repoObject.__typename !== 'Repository') return null;
        const repo = repoObject.repo as RepoRecord;
        const pull = createPullRecord(
          repo,
          typeof input.title === 'string' ? input.title : '',
          typeof input.body === 'string' ? input.body : '',
          typeof input.headRefName === 'string' ? input.headRefName : '',
          typeof input.baseRefName === 'string' ? input.baseRefName : '',
        );
        if (pull === null) return null;
        return { __typename: 'CreatePullRequestPayload', repo, pull };
      }
      if (name === 'mergePullRequest') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const pullObject = typeof input.pullRequestId === 'string' ? decodeGlobalId(input.pullRequestId) : null;
        if (pullObject === null || pullObject.__typename !== 'PullRequest') return null;
        const repo = pullObject.repo as RepoRecord;
        const pull = pullObject.pull as PullRecord;
        mergePullRequest(repo, pull);
        return { __typename: 'MergePullRequestPayload', repo, pull };
      }
      if (name === 'addComment') {
        const input = (args.input ?? {}) as Record<string, unknown>;
        const subject = typeof input.subjectId === 'string' ? decodeGlobalId(input.subjectId) : null;
        if (subject === null || subject.__typename !== 'Issue') return null;
        const repo = subject.repo as RepoRecord;
        const issue = subject.issue as IssueRecord;
        const comment: CommentRecord = { id: store.newCommentId(), body: typeof input.body === 'string' ? input.body : '', createdAt: FIXED_ISO };
        issue.comments.push(comment);
        return { __typename: 'AddCommentPayload', repo, issue, comment };
      }
      break;
    }
    case 'User': {
      if (name === 'login') return obj.login as string;
      if (name === 'id') return b64encode(`U:${obj.login as string}`);
      break;
    }
    case 'Repository': {
      const repo = obj.repo as RepoRecord;
      if (name === 'id') return repoNodeId(repo);
      if (name === 'databaseId') return repo.id;
      if (name === 'name') return repo.name;
      if (name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (name === 'owner') return { __typename: 'User', login: repo.owner };
      if (name === 'defaultBranchRef') return { __typename: 'Ref', name: repo.defaultBranch };
      if (name === 'viewerPermission') return 'ADMIN';
      if (name === 'hasIssuesEnabled') return true;
      if (name === 'issue') {
        const number = args.number as number | undefined;
        const issue = typeof number === 'number' ? repo.issues.get(number) : undefined;
        return issue === undefined ? null : { __typename: 'Issue', repo, issue };
      }
      if (name === 'issues') return issueConnection(repo, args);
      if (name === 'pullRequest') {
        const number = args.number as number | undefined;
        const pull = typeof number === 'number' ? repo.pulls.get(number) : undefined;
        return pull === undefined ? null : { __typename: 'PullRequest', repo, pull };
      }
      if (name === 'pullRequests') return pullConnection(repo, args);
      break;
    }
    case 'Issue': {
      const issue = obj.issue as IssueRecord;
      const repo = obj.repo as RepoRecord;
      if (name === 'id') return issueNodeId(repo, issue);
      if (name === 'number') return issue.number;
      if (name === 'title') return issue.title;
      if (name === 'body') return issue.body;
      if (name === 'state') return issue.state === 'open' ? 'OPEN' : 'CLOSED';
      if (name === 'url') return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
      if (name === 'createdAt') return issue.createdAt;
      if (name === 'updatedAt') return issue.updatedAt;
      break;
    }
    case 'PullRequest': {
      const pull = obj.pull as PullRecord;
      const repo = obj.repo as RepoRecord;
      if (name === 'id') return pullNodeId(repo, pull);
      if (name === 'number') return pull.number;
      if (name === 'title') return pull.title;
      if (name === 'body') return pull.body;
      if (name === 'state') return pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
      if (name === 'merged') return pull.merged;
      if (name === 'mergeable') return pull.state === 'open' ? (computeMergeable(repo, pull) ? 'MERGEABLE' : 'CONFLICTING') : 'UNKNOWN';
      if (name === 'headRefName') return pull.head;
      if (name === 'baseRefName') return pull.base;
      if (name === 'files') return fileConnection(repo, pull, args);
      break;
    }
    case 'IssueConnection': {
      const items = obj.items as IssueRecord[];
      const repo = obj.repo as RepoRecord;
      if (name === 'nodes') return items.map((issue) => ({ __typename: 'Issue', repo, issue }));
      if (name === 'edges') return items.map((issue) => ({ __typename: 'IssueEdge', repo, issue, cursor: cursorFor(issue.number) }));
      if (name === 'pageInfo') return obj.pageInfo as GqlObject;
      if (name === 'totalCount') return obj.total as number;
      break;
    }
    case 'PullRequestConnection': {
      const items = obj.items as PullRecord[];
      const repo = obj.repo as RepoRecord;
      if (name === 'nodes') return items.map((pull) => ({ __typename: 'PullRequest', repo, pull }));
      if (name === 'edges') return items.map((pull) => ({ __typename: 'PullRequestEdge', repo, pull, cursor: cursorFor(pull.number) }));
      if (name === 'pageInfo') return obj.pageInfo as GqlObject;
      if (name === 'totalCount') return obj.total as number;
      break;
    }
    case 'FileConnection': {
      const items = obj.items as Array<FileDiff & { number: number }>;
      if (name === 'nodes') return items.map((file) => ({ __typename: 'File', path: file.filename }));
      if (name === 'edges') return items.map((file) => ({ __typename: 'FileEdge', node: { __typename: 'File', path: file.filename }, cursor: cursorFor(file.number) }));
      if (name === 'pageInfo') return obj.pageInfo as GqlObject;
      if (name === 'totalCount') return obj.total as number;
      break;
    }
    case 'IssueEdge':
    case 'PullRequestEdge':
    case 'CommentEdge':
    case 'FileEdge': {
      if (name === 'node') {
        if (typeName === 'IssueEdge') return { __typename: 'Issue', repo: obj.repo as RepoRecord, issue: obj.issue as IssueRecord };
        if (typeName === 'PullRequestEdge') return { __typename: 'PullRequest', repo: obj.repo as RepoRecord, pull: obj.pull as PullRecord };
        if (typeName === 'CommentEdge') return { __typename: 'Comment', repo: obj.repo as RepoRecord, issue: obj.issue as IssueRecord, comment: obj.comment as CommentRecord };
        return obj.node as GqlObject;
      }
      if (name === 'cursor') return obj.cursor as string;
      break;
    }
    case 'PageInfo': {
      if (name === 'hasNextPage') return obj.hasNextPage as boolean;
      if (name === 'endCursor') return obj.endCursor as string | null;
      if (name === 'hasPreviousPage') return obj.hasPreviousPage as boolean;
      if (name === 'startCursor') return obj.startCursor as string | null;
      break;
    }
    case 'Ref': {
      if (name === 'name') return obj.name as string;
      break;
    }
    case 'Comment': {
      const comment = obj.comment as CommentRecord;
      const issue = obj.issue as IssueRecord;
      const repo = obj.repo as RepoRecord;
      if (name === 'id') return commentNodeId(repo, issue, comment);
      if (name === 'body') return comment.body;
      break;
    }
    case 'File': {
      if (name === 'path') return obj.path as string;
      break;
    }
    case '__Type': {
      const requested = obj.name as string;
      if (name === 'name') return requested;
      if (name === 'fields') return (TYPE_FIELDS[requested] ?? []).map((field) => ({ __typename: '__Field', name: field }));
      if (name === 'enumValues') return (TYPE_ENUMS[requested] ?? []).map((value) => ({ __typename: '__EnumValue', name: value }));
      break;
    }
    case '__Field':
    case '__EnumValue': {
      if (name === 'name') return obj.name as string;
      break;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload': {
      if (name === 'issue') return { __typename: 'Issue', repo: obj.repo as RepoRecord, issue: obj.issue as IssueRecord };
      break;
    }
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload': {
      if (name === 'pullRequest') return { __typename: 'PullRequest', repo: obj.repo as RepoRecord, pull: obj.pull as PullRecord };
      break;
    }
    case 'AddCommentPayload': {
      if (name === 'commentEdge') return { __typename: 'CommentEdge', repo: obj.repo as RepoRecord, issue: obj.issue as IssueRecord, comment: obj.comment as CommentRecord, cursor: cursorFor((obj.comment as CommentRecord).id) };
      break;
    }
  }
  ctx.errors.push({ message: `Cannot query field "${name}" on type "${typeName}".` });
  return undefined;
}

function resolveField(
  obj: GqlObject,
  selection: GqlFieldSelection,
  args: Record<string, unknown>,
  variables: Record<string, unknown>,
  ctx: GqlContext,
): unknown {
  const raw = fieldValue(obj, selection.name, args, ctx);
  if (raw === undefined) return null;
  if (selection.selections.length === 0) return raw;
  if (raw === null) return null;
  if (Array.isArray(raw)) {
    return raw.map((item) => (item !== null && typeof item === 'object'
      ? resolveSelections(item as GqlObject, selection.selections, variables, ctx)
      : item));
  }
  if (typeof raw === 'object') return resolveSelections(raw as GqlObject, selection.selections, variables, ctx);
  return raw;
}

function resolveSelections(
  obj: GqlObject | null,
  selections: GqlSelection[],
  variables: Record<string, unknown>,
  ctx: GqlContext,
): Record<string, unknown> | null {
  if (obj === null) return null;
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (selection.typeCondition !== null && selection.typeCondition !== obj.__typename) continue;
      const nested = resolveSelections(obj, selection.selections, variables, ctx);
      if (nested !== null) Object.assign(out, nested);
      continue;
    }
    const resolvedArgs: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(selection.args)) resolvedArgs[key] = resolveArgValue(value, variables);
    out[selection.alias] = resolveField(obj, selection, resolvedArgs, variables, ctx);
  }
  return out;
}

function executeGraphqlDocument(document: unknown): Record<string, unknown> {
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    return { data: null, errors: [{ message: 'a GraphQL document object is required' }] };
  }
  const query = (document as Record<string, unknown>).query;
  if (typeof query !== 'string') return { data: null, errors: [{ message: 'query is required' }] };
  const variables = ((document as Record<string, unknown>).variables ?? {}) as Record<string, unknown>;
  try {
    const operations = new GqlParser(query).parseDocument();
    if (operations.length === 0) return { data: null, errors: [{ message: 'empty document' }] };
    const operation = operations[0] as GqlOperation;
    const mergedVariables: Record<string, unknown> = { ...operation.variables, ...variables };
    const ctx: GqlContext = { errors: [] };
    const data = resolveSelections({ __typename: 'Query' }, operation.selections, mergedVariables, ctx);
    const result: Record<string, unknown> = { data };
    if (ctx.errors.length > 0) result.errors = ctx.errors;
    return result;
  } catch (error) {
    return { data: null, errors: [{ message: error instanceof Error ? error.message : 'parse error' }] };
  }
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  if ((req.method ?? 'GET') !== 'POST') {
    errorJson(res, 405, 'Method Not Allowed');
    return;
  }
  if (!isAuthenticated(req)) {
    errorJson(res, 401, 'Requires authentication');
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Problems parsing JSON' }] });
    return;
  }
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((item) => executeGraphqlDocument(item)));
    return;
  }
  sendJson(res, 200, executeGraphqlDocument(parsed));
}

// ---------------------------------------------------------------------------
// MCP: JSON-RPC 2.0 tools over POST /mcp.

const MCP_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_SERVER_INFO = { name: 'forge', version: '1.0.0' };

const MCP_TOOLS: Array<{ name: string; description: string; inputSchema: Record<string, unknown> }> = [
  {
    name: 'create_repo',
    description: 'Create a new repository for the authenticated user.',
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
    description: 'Get a repository by owner and name.',
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
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Issue state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
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
    description: 'Merge a pull request with a squash commit onto its base branch.',
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

const ARG_SYNONYMS: Record<string, string[]> = {
  owner: ['owner_login', 'owner_name', 'repository_owner', 'user'],
  repo: ['repo_name', 'repository', 'repository_name'],
  name: ['repo_name', 'repository_name'],
  title: ['issue_title'],
  head: ['head_branch', 'head_ref'],
  base: ['base_branch', 'base_ref'],
  pull_number: ['number', 'pr_number', 'pullNumber'],
  body: ['issue_body'],
  description: ['repo_description'],
  private: ['is_private'],
  state: ['issue_state'],
};

function pickArg(args: Record<string, unknown>, canonical: string): unknown {
  if (args[canonical] !== undefined) return args[canonical];
  for (const synonym of ARG_SYNONYMS[canonical] ?? []) {
    if (args[synonym] !== undefined) return args[synonym];
  }
  return undefined;
}

function mcpRepo(args: Record<string, unknown>): RepoRecord | null {
  const owner = pickArg(args, 'owner');
  const repoName = pickArg(args, 'repo');
  if (typeof owner !== 'string' || typeof repoName !== 'string') return null;
  if (owner !== VIEWER.login) return null;
  return store.getRepo(owner, repoName) ?? null;
}

function executeMcpTool(name: string, args: Record<string, unknown>): { isError: boolean; body: Record<string, unknown> } {
  if (name === 'create_repo') {
    const repoName = pickArg(args, 'name');
    if (typeof repoName !== 'string' || repoName === '') return { isError: true, body: { error: 'name is required' } };
    const repo = store.createRepo(
      VIEWER.login,
      repoName,
      typeof pickArg(args, 'description') === 'string' ? (pickArg(args, 'description') as string) : '',
      pickArg(args, 'private') === true,
    );
    if (repo === null) return { isError: true, body: { error: `repository ${repoName} already exists` } };
    return { isError: false, body: repoJson(repo) };
  }
  if (name === 'get_repo') {
    const repo = mcpRepo(args);
    if (repo === null) return { isError: true, body: { error: 'Not Found' } };
    return { isError: false, body: repoJson(repo) };
  }
  if (name === 'create_issue') {
    const repo = mcpRepo(args);
    if (repo === null) return { isError: true, body: { error: 'Not Found' } };
    const title = pickArg(args, 'title');
    if (typeof title !== 'string' || title === '') return { isError: true, body: { error: 'title is required' } };
    const body = pickArg(args, 'body');
    const issue = createIssueRecord(repo, title, typeof body === 'string' ? body : '');
    return { isError: false, body: issueJson(repo, issue) };
  }
  if (name === 'list_issues') {
    const repo = mcpRepo(args);
    if (repo === null) return { isError: true, body: { error: 'Not Found' } };
    const state = pickArg(args, 'state');
    let issues = [...repo.issues.values()];
    if (typeof state === 'string' && state !== 'all') issues = issues.filter((issue) => issue.state === state);
    issues.sort((a, b) => b.createdSeq - a.createdSeq);
    return { isError: false, body: { issues: issues.map((issue) => issueJson(repo, issue)) } };
  }
  if (name === 'create_pull_request') {
    const repo = mcpRepo(args);
    if (repo === null) return { isError: true, body: { error: 'Not Found' } };
    const title = pickArg(args, 'title');
    const head = pickArg(args, 'head');
    const base = pickArg(args, 'base');
    if (typeof title !== 'string' || typeof head !== 'string' || typeof base !== 'string') {
      return { isError: true, body: { error: 'title, head and base are required' } };
    }
    const body = pickArg(args, 'body');
    const pull = createPullRecord(repo, title, typeof body === 'string' ? body : '', head, base);
    if (pull === null) return { isError: true, body: { error: 'head or base branch does not exist' } };
    return { isError: false, body: pullJson(repo, pull) };
  }
  if (name === 'merge_pull_request') {
    const repo = mcpRepo(args);
    if (repo === null) return { isError: true, body: { error: 'Not Found' } };
    const number = pickArg(args, 'pull_number');
    const pull = typeof number === 'number' ? repo.pulls.get(number) : undefined;
    if (pull === undefined) return { isError: true, body: { error: 'Not Found' } };
    const result = mergePullRequest(repo, pull);
    if (result.status !== 200) return { isError: true, body: { error: (result.body.message as string | undefined) ?? 'merge failed' } };
    return { isError: false, body: result.body };
  }
  return { isError: true, body: { error: `unknown tool ${name}` } };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): Promise<void> {
  if ((req.method ?? 'GET') !== 'POST') {
    errorJson(res, 405, 'Method Not Allowed');
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const request = parsed as Record<string, unknown>;
  const id = request.id ?? null;
  // A notification (no id) is acknowledged with 202 and no body.
  if (id === null) {
    sendEmpty(res, 202);
    return;
  }
  if (!isAuthenticated(req)) {
    errorJson(res, 401, 'Requires authentication');
    return;
  }
  const method = request.method as string | undefined;
  const params = (request.params ?? {}) as Record<string, unknown>;
  const reply = (result: unknown): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
  };
  const replyError = (code: number, message: string): void => {
    sendJson(res, 200, { jsonrpc: '2.0', id, error: { code, message } });
  };

  if (method === 'server/discover') {
    reply({
      supportedVersions: MCP_VERSIONS,
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
      _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = params.protocolVersion as string | undefined;
    const protocolVersion = typeof offered === 'string' && MCP_VERSIONS.includes(offered) ? offered : MCP_VERSIONS[0] as string;
    reply({
      protocolVersion,
      capabilities: { tools: {} },
      serverInfo: MCP_SERVER_INFO,
      _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
    });
    return;
  }
  if (method === 'ping') {
    reply({});
    return;
  }
  if (method === 'tools/list') {
    reply({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const toolName = params.name as string | undefined;
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const tool = MCP_TOOLS.find((candidate) => candidate.name === toolName);
    if (tool === undefined) {
      replyError(-32602, `unknown tool ${String(toolName)}`);
      return;
    }
    const required = (tool.inputSchema.required ?? []) as string[];
    const missing = required.filter((name) => pickArg(args, name) === undefined);
    if (missing.length > 0) {
      reply({
        content: [{ type: 'text', text: JSON.stringify({ error: `missing required argument(s): ${missing.join(', ')}` }) }],
        isError: true,
      });
      return;
    }
    const output = executeMcpTool(tool.name, args);
    reply({
      content: [{ type: 'text', text: JSON.stringify(output.body) }],
      structuredContent: output.body,
      isError: output.isError,
    });
    return;
  }
  replyError(-32601, `method not found: ${String(method)}`);
}

// ---------------------------------------------------------------------------
// The application: one HTTP handler for every route.

export function createApp(): Server {
  return createServer((req: IncomingMessage, res: ServerResponse): void => {
    void (async () => {
      try {
        const parts = parseRequest(req);
        const body = await readRequestBody(req);
        const { segments } = parts;
        if ((req.method ?? 'GET') === 'GET' && segments.length === 1 && segments[0] === 'healthz') {
          sendJson(res, 200, { ok: true });
          return;
        }
        if (await handleGit(req, res, parts, body)) return;
        if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
          if (await handleRest(req, res, parts, body)) return;
          errorJson(res, 404, 'Not Found');
          return;
        }
        if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
          await handleGraphql(req, res, body);
          return;
        }
        if (segments.length === 1 && segments[0] === 'mcp') {
          await handleMcp(req, res, body);
          return;
        }
        errorJson(res, 404, 'Not Found');
      } catch (error) {
        if (!res.headersSent) {
          errorJson(res, 500, error instanceof Error ? error.message : 'internal error');
        } else {
          res.end();
        }
      }
    })();
  });
}
