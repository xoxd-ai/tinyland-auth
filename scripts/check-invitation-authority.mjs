import { access, readFile } from 'node:fs/promises';
import ts from 'typescript';

// TIN-2780 standing tripwire. tinyland-auth once re-exported its own ungated
// InvitationService whose createInvitation performs NO role authorization
// (options.role flowed straight into the minted invite). The authoritative,
// fail-closed invite flow is the standalone @tummycrypt/tinyland-invitation
// package (TIN-1607, tinyland.dev PR #649).
//
// PR #34 kept the local invitation module but internalized it: it is removed
// from src/index.ts and unreachable via the package "exports" map. This guard is
// a stronger standing check than tests/invitation-not-exported.test.ts — it
// parses BOTH the source index and the GENERATED declaration surface, so an
// authority leak via a wildcard or transitive re-export in the emitted
// dist/index.d.ts is caught too, and it verifies the retained type-only
// compatibility exports remain present.
//
// Bazel //:invitation_authority_test supplies the :tinyland_auth_types output,
// including dist/index.d.ts. A source-only check is not a replacement.

const surfaces = ['src/index.ts', 'dist/index.d.ts'];
const retainedCompatibilityTypes = [
  'AdminInvitation',
  'InvitationConfig',
  'InvitationStorage',
  'InvitationCreateRequest',
  'InvitationCreateResponse',
  'InvitationAcceptRequest',
  'InvitationAcceptResponse',
  'InvitationListResponse',
  'InvitationRevokeRequest',
  'InvitationRevokeResponse',
];

// The internal, unreachable module #34 retained. It must NOT be re-exported from
// the public index (source or emitted declaration).
const internalModuleSpecifier = /['"]\.\/modules\/invitation(?:\/index)?(?:\.js)?['"]/;

function exportedNames(source, filename) {
  const sourceFile = ts.createSourceFile(
    filename,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const names = new Set();

  for (const statement of sourceFile.statements) {
    if (
      ts.isExportDeclaration(statement) &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause)
    ) {
      for (const element of statement.exportClause.elements) {
        names.add(element.name.text);
      }
      continue;
    }

    const exported = statement.modifiers?.some(
      (modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword,
    );
    if (!exported) continue;

    if ('name' in statement && statement.name && ts.isIdentifier(statement.name)) {
      names.add(statement.name.text);
    }

    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) {
          names.add(declaration.name.text);
        }
      }
    }
  }

  return names;
}

function isExecutableInvitationAuthority(name) {
  return (
    /^(?:create|mint|issue|accept|revoke|extend|list|get|generate)(?:Invitation|Invite)/i.test(
      name,
    ) ||
    /^(?:Invitation|Invite).*(?:Service|Factory|Manager|Authority)/i.test(name)
  );
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function readSurface(surface) {
  if (await exists(surface)) {
    return readFile(surface, 'utf8');
  }
  if (surface.startsWith('dist/')) {
    throw new Error(
      `${surface} not found — the Bazel invitation_authority_test requires generated :tinyland_auth declarations`,
    );
  }
  throw new Error(`${surface} not found`);
}

const failures = [];

for (const surface of surfaces) {
  const source = await readSurface(surface);
  const names = exportedNames(source, surface);
  const executableExports = [...names].filter(isExecutableInvitationAuthority);

  if (executableExports.length > 0) {
    failures.push(`${surface} exports invitation authority: ${executableExports.join(', ')}`);
  }

  // The internalized duplicate implementation (retained by #34) must never be
  // re-exported from the public index. A restored re-export brings the ungated
  // minter back onto the public surface.
  if (internalModuleSpecifier.test(source)) {
    failures.push(`${surface} re-exports the internal invitation module (ungated authority leak)`);
  }

  for (const retained of retainedCompatibilityTypes) {
    if (!names.has(retained)) {
      failures.push(`${surface} no longer exports retained compatibility type ${retained}`);
    }
  }
}

const packageJson = JSON.parse(await readFile('package.json', 'utf8'));
const invitationSubpaths = Object.keys(packageJson.exports ?? {}).filter((path) =>
  /invitation|invite/i.test(path),
);
if (invitationSubpaths.length > 0) {
  failures.push(`package.json exposes invitation subpaths: ${invitationSubpaths.join(', ')}`);
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`invitation authority error: ${failure}`);
  }
  process.exit(1);
}

console.log(
  `invitation authority surface clean; retained compatibility types: ${retainedCompatibilityTypes.join(', ')}`,
);
