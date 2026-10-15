/**
 * Admin user repository (folded from @tummycrypt/tinyland-admin-user-repository
 * 0.2.4 candidate 46c8cbdcc2 under RV15; that repository stays archived).
 */
export {
	configure,
	getConfig,
	resetConfig,
} from './config.js';

export type {
	AdminUserRepositoryConfig,
} from './config.js';


export {
	PUBLIC_ADMIN_USER_FIELDS,
} from './types.js';

export type {
	AdminUser,
	PublicAdminUser,
	PublicHandleIdentity,
	StoredAdminUserData,
	CreateUserData,
} from './types.js';


export {
	AdminUserRepository,
	adminUserRepository,
} from './repository.js';

export {
	type PublicHandleDirectoryBackingFile,
	type PublicHandleDirectorySource,
	type PublicHandleDirectorySourceModel,
	PUBLIC_HANDLE_DIRECTORY_BACKING_FILE,
	PUBLIC_HANDLE_DIRECTORY_BACKING_SURFACE,
	PUBLIC_HANDLE_DIRECTORY_SOURCE_MODEL,
	createPublicHandleDirectory,
	type PublicHandleDirectory,
	repositoryBackedPublicHandleDirectorySource,
	publicHandleDirectory,
} from './publicHandleDirectory.js';
