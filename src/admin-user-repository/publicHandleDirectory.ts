import type { PublicHandleIdentity } from './types.js';
import { adminUserRepository } from './repository.js';

export type PublicHandleDirectorySourceModel =
	| 'repository_backed_admin_identity'
	| (string & {});

export const PUBLIC_HANDLE_DIRECTORY_SOURCE_MODEL: PublicHandleDirectorySourceModel =
	'repository_backed_admin_identity';

export const PUBLIC_HANDLE_DIRECTORY_BACKING_FILE = 'content/auth/admin-users.json' as const;
export const PUBLIC_HANDLE_DIRECTORY_BACKING_SURFACE = PUBLIC_HANDLE_DIRECTORY_BACKING_FILE;
export type PublicHandleDirectoryBackingFile = typeof PUBLIC_HANDLE_DIRECTORY_BACKING_FILE | null;

export interface PublicHandleDirectorySource {
	readonly sourceModel: PublicHandleDirectorySourceModel;
	readonly backingSurface: string;
	readonly backingFile?: PublicHandleDirectoryBackingFile;
	findByHandle(handle: string): Promise<PublicHandleIdentity | null>;
	findAll(): Promise<PublicHandleIdentity[]>;
}

export interface PublicHandleDirectory {
	readonly sourceModel: PublicHandleDirectorySourceModel;
	readonly backingSurface: string;
	readonly backingFile: PublicHandleDirectoryBackingFile;
	findByHandle(handle: string): Promise<PublicHandleIdentity | null>;
	findAll(): Promise<PublicHandleIdentity[]>;
}

class DefaultPublicHandleDirectory implements PublicHandleDirectory {
	readonly sourceModel: PublicHandleDirectorySourceModel;
	readonly backingSurface: string;
	readonly backingFile: PublicHandleDirectoryBackingFile;

	constructor(private readonly source: PublicHandleDirectorySource) {
		this.sourceModel = source.sourceModel;
		this.backingSurface = source.backingSurface;
		this.backingFile = source.backingFile ?? null;
	}

	async findByHandle(handle: string): Promise<PublicHandleIdentity | null> {
		return this.source.findByHandle(handle);
	}

	async findAll(): Promise<PublicHandleIdentity[]> {
		return this.source.findAll();
	}
}

export const repositoryBackedPublicHandleDirectorySource: PublicHandleDirectorySource = {
	sourceModel: PUBLIC_HANDLE_DIRECTORY_SOURCE_MODEL,
	backingSurface: PUBLIC_HANDLE_DIRECTORY_BACKING_SURFACE,
	backingFile: PUBLIC_HANDLE_DIRECTORY_BACKING_FILE,
	findByHandle: (handle: string) => adminUserRepository.findPublicHandleIdentity(handle),
	findAll: () => adminUserRepository.findAllPublicHandleIdentities(),
};

export function createPublicHandleDirectory(
	source: PublicHandleDirectorySource,
): PublicHandleDirectory {
	return new DefaultPublicHandleDirectory(source);
}

export const publicHandleDirectory: PublicHandleDirectory =
	createPublicHandleDirectory(repositoryBackedPublicHandleDirectorySource);
