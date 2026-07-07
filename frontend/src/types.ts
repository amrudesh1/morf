// Data shapes ported verbatim from the Angular scan.service.ts contract.
// These must match the backend responses exactly — do not change field names.

export type Platform = 'android' | 'ios'
export type Confidence = 'high' | 'medium' | 'low'
export type Screen = 'splash' | 'upload' | 'processing' | 'results' | 'patterns'
export type JobStatus = 'queued' | 'processing' | 'completed' | 'failed' | 'cancelled'

export interface Secret {
  type: string
  lineNo: number
  secretType: string
  fileLocation: string
  secretString: string
  secretConfidence: Confidence
}

export interface IosMetadata {
  bundleIdentifier: string
  bundleVersion: string
  deploymentTarget: string
  executableName: string
  architectures: string[]
  isEncrypted: boolean
  urlSchemes: string[]
  entitlements: Record<string, unknown>
  frameworks: string[]
}

export interface IntentData {
  scheme: string
  host: string
  path: string
  pathPrefix: string[]
  pathPattern: string
  port: string
  mimeType: string
}
export interface IntentFilter {
  actions: string[]
  data: IntentData[]
  priority: number
}
export interface Activity {
  name: string
  exported: boolean
  intentFilters: IntentFilter[]
}
export interface NamedComponent {
  name: string
  exported: boolean
}
export interface ResourceData {
  numberOfStringResource: number
  drawables: { png: number; jpg: number; gif: number; xml: number }
  layouts: number
}
export interface Metadata {
  packageName: string
  version: string
  minSdk: string
  targetSdk: string
  permissions: string[]
  activities: Activity[]
  services: NamedComponent[]
  contentProviders: NamedComponent[]
  broadcastReceivers: NamedComponent[]
  usesLibrary: string[]
  customPermissions: string[]
  usesFeatures: string[]
  resourceData: ResourceData
}

// Wire formats -------------------------------------------------------------
export interface BackendSecret {
  type: string
  lineNo: number
  secretType: string
  fileLocation: string
  secretString: string
  secretConfidence: Confidence
}
export interface ScanResponseData {
  platform?: Platform
  fileName?: string
  packageName?: string
  version?: string
  minSdk?: string
  targetSdk?: string
  permissions?: string[]
  secretCount?: number
  secrets?: BackendSecret[]
  // iOS
  bundleIdentifier?: string
  bundleVersion?: string
  deploymentTarget?: string
  executableName?: string
  architectures?: string[]
  isEncrypted?: boolean
  urlSchemes?: string[]
  entitlements?: Record<string, unknown>
  frameworks?: string[]
  // Android
  activities?: Activity[]
  services?: NamedComponent[]
  contentProviders?: NamedComponent[]
  broadcastReceivers?: NamedComponent[]
  usesLibrary?: string[]
  customPermissions?: string[]
  usesFeatures?: string[]
  resourceData?: ResourceData
}
export interface ScanResponse {
  message: string
  data: ScanResponseData
}
export interface UploadResponse {
  message: string
  job_id: string
}
export interface JobStatusResponse {
  job_id: string
  status: JobStatus
  created_at: string
  started_at?: string
  completed_at?: string
  failed_at?: string
  error?: string
  result?: ScanResponse
}

// Pattern management -------------------------------------------------------
export interface Pattern {
  name: string
  regex: string
  confidence: Confidence
  enabled: boolean
}
export interface PatternFile {
  filename: string
  patterns: Pattern[]
}
export interface PatternListResponse {
  files: PatternFile[]
  total: number
}
export interface PatternTestResponse {
  matched: boolean
  matches: string[]
  count: number
}
