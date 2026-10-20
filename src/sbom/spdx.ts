import { packageVersion } from '../core/version.js';
import { spdxCreated } from './spdx-time.js';
import { componentKey, type SpdxComponent, type SpdxPair, type SpdxProject, loadSpdxProject } from './spdx-load.js';

interface SpdxBuildOptions {
  created?: string;
  /** CycloneDX path written in this same command. Omitted when SPDX is the only document. */
  cyclonedxFile?: string;
}

export async function buildSpdxSbom(cwd: string, options: SpdxBuildOptions = {}): Promise<Record<string, unknown>> {
  return renderSpdx(await loadSpdxProject(cwd), options);
}

function renderSpdx(project: SpdxProject, options: SpdxBuildOptions = {}): Record<string, unknown> {
  const created = spdxCreated(options.created);
  const ids = assignIds(project.components);
  const packages = project.components
    .map((component) => toPackage(component, ids.get(componentKey(component)) ?? ''))
    .sort((left, right) => String(left.SPDXID).localeCompare(String(right.SPDXID)));
  const root = project.components.find((component) => component.role === 'root');
  const rootId = root === undefined ? 'SPDXRef-DOCUMENT' : (ids.get(componentKey(root)) ?? 'SPDXRef-DOCUMENT');
  const doc: Record<string, unknown> = {
    SPDXID: 'SPDXRef-DOCUMENT',
    creationInfo: { created, creators: [toolCreator()] },
    dataLicense: 'CC0-1.0',
    documentNamespace: `urn:spdx:fullshield:${encodeURIComponent(project.name)}:${encodeURIComponent(project.version)}`,
    name: project.name,
    packages,
    relationships: relationships(rootId, ids, project.dependsOn),
    spdxVersion: 'SPDX-2.3',
  };
  const notes = cycloneAnnotation(created, options.cyclonedxFile);
  if (notes !== undefined) {doc.annotations = notes;}
  return canonicalize(doc) as Record<string, unknown>;
}

function toolCreator(): string {
  return `Tool: fullshield-${packageVersion()}`;
}

function assignIds(components: SpdxComponent[]): Map<string, string> {
  const used = new Set<string>();
  const ids = new Map<string, string>();
  const ordered = [...components].sort((left, right) => componentKey(left).localeCompare(componentKey(right)));
  for (const component of ordered) {ids.set(componentKey(component), uniqueId(baseId(component), used));}
  return ids;
}

function baseId(component: SpdxComponent): string {
  const role = component.role === 'root' ? 'Root' : 'Package';
  const safe = `${role}-${component.name}-${component.version}`.replace(/[^A-Za-z0-9.-]+/g, '-');
  return `SPDXRef-${safe}`;
}

function uniqueId(base: string, used: Set<string>): string {
  if (!used.has(base)) {
    used.add(base);
    return base;
  }
  let n = 2;
  let candidate = `${base}-${n}`;
  while (used.has(candidate)) {
    n += 1;
    candidate = `${base}-${n}`;
  }
  used.add(candidate);
  return candidate;
}

function npmPurl(name: string, version: string): string {
  const slash = name.indexOf('/');
  const encoded =
    name.startsWith('@') && slash > 0
      ? `${encodeURIComponent(name.slice(0, slash))}/${name.slice(slash + 1)}`
      : encodeURIComponent(name);
  return `pkg:npm/${encoded}@${encodeURIComponent(version)}`;
}

function toPackage(component: SpdxComponent, id: string): Record<string, unknown> {
  return {
    SPDXID: id,
    copyrightText: 'NOASSERTION',
    downloadLocation: component.downloadLocation ?? 'NOASSERTION',
    externalRefs: [
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceLocator: npmPurl(component.name, component.version),
        referenceType: 'purl',
      },
    ],
    filesAnalyzed: false,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: component.license ?? 'NOASSERTION',
    name: component.name,
    versionInfo: component.version,
  };
}

function relationships(rootId: string, ids: Map<string, string>, pairs: SpdxPair[]): Array<Record<string, string>> {
  const rels: Array<Record<string, string>> = [
    { relatedSpdxElement: rootId, relationshipType: 'DESCRIBES', spdxElementId: 'SPDXRef-DOCUMENT' },
  ];
  for (const pair of pairs) {
    const from = ids.get(pair.from);
    const to = ids.get(pair.to);
    if (from === undefined || to === undefined) {continue;}
    rels.push({ relatedSpdxElement: to, relationshipType: 'DEPENDS_ON', spdxElementId: from });
  }
  return rels.sort((left, right) => relationshipKey(left).localeCompare(relationshipKey(right)));
}

function relationshipKey(rel: Record<string, string>): string {
  return `${rel.spdxElementId}|${rel.relationshipType}|${rel.relatedSpdxElement}`;
}

function cycloneAnnotation(created: string, cyclonedxFile: string | undefined): Array<Record<string, string>> | undefined {
  if (cyclonedxFile === undefined || cyclonedxFile.length === 0) {return undefined;}
  return [
    {
      annotationDate: created,
      annotationType: 'OTHER',
      annotator: toolCreator(),
      comment: `Vulnerability data is in the CycloneDX file ${cyclonedxFile}`,
    },
  ];
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {return value.map(canonicalize);}
  if (value === null || typeof value !== 'object') {return value;}
  const source = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(source).sort()) {
    const child = source[key];
    if (child !== undefined) {sorted[key] = canonicalize(child);}
  }
  return sorted;
}
