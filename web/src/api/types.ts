export type Problem = {
  type: string;
  title: string;
  status: number;
  detail: string;
  code: string;
};

export type SessionCreated = {
  csrf: string;
  expiresAt: string;
};

export type SessionView = {
  id: string;
  role: string;
  scopes: string[];
  csrf?: string;
  expiresAt?: string;
};

export type Header = {
  name: string;
  value: string;
};

export type HTTPMessage = {
  headers?: Header[];
  trailers?: Header[];
  body?: string;
  size: number;
  truncated: boolean;
};

export type HTTP2Info = {
  streamId: number;
};

export type SOCKSInfo = {
  version?: number;
  atyp?: string;
  dest?: string;
  command?: string;
  bnd?: string;
};

export type TLSInfo = {
  sni?: string;
  version?: string;
  cipherSuite?: string;
  alpn?: string;
  upstreamVerified: boolean;
  leafDns?: string[];
};

export type Timings = {
  dnsMs: number;
  connectMs: number;
  tlsMs: number;
  ttfbMs: number;
  totalMs: number;
};

export type Flow = {
  id: string;
  startedAt?: string;
  completedAt?: string;
  state: string;
  pausedPhase?: string;
  clientAddr?: string;
  method: string;
  url: string;
  host: string;
  scheme: string;
  protocol: string;
  status: number;
  error?: string;
  intercepted: boolean;
  request: HTTPMessage;
  response: HTTPMessage;
  tls?: TLSInfo;
  http2?: HTTP2Info;
  socks?: SOCKSInfo;
  via?: string;
  originalDest?: string;
  timings: Timings;
  ruleIds?: string[];
  truncated: boolean;
  requestBytes: number;
  responseBytes: number;
};

export type FlowList = {
  revision: string;
  storeGeneration: number;
  items: Flow[];
  nextCursor: string | null;
};

export type StoreStats = {
  flowCount: number;
  storeBytes: number;
  storeGeneration: number;
  epoch: number;
};

export type Listener = {
  name: string;
  address: string;
};

export type CAStatus = {
  mode?: string;
  spkiSha256?: string;
  subject?: string;
  notAfter?: string;
};

export type StatusFeatures = {
  http2: boolean;
  http2ClientCleartext: boolean;
  http2Origin: boolean;
  http2ExtendedConnect: boolean;
  http2CapturePush: boolean;
  http2GRPCDecode: boolean;
  inspectWebSocketFrames: boolean;
  socks5: boolean;
  socks4: boolean;
  acceptBind: boolean;
  acceptUDPAssociate: boolean;
  acceptUserPass: boolean;
  originalDestination: boolean;
  compatFlowREST: boolean;
};

export type Status = {
  ready: boolean;
  revisions: Record<string, unknown>;
  listeners: Listener[];
  store: StoreStats;
  intercept: boolean;
  ca: CAStatus;
  features: StatusFeatures;
};

export type AuditEvent = {
  id: string;
  time: string;
  actorId?: string;
  actorClass?: string;
  transport?: string;
  capability?: string;
  reason?: string;
  flowId?: string;
  previous?: string;
  revision?: string;
  storeGeneration?: number;
  result?: string;
  errorCode?: string;
};

export type AuditList = {
  events: AuditEvent[];
};

export type FlowListQuery = {
  host?: string;
  method?: string;
  status?: string;
  scheme?: string;
  intercepted?: string;
};
