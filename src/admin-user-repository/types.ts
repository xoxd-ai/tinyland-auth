export interface AdminUser {
	id: string;
	username: string;
	handle?: string;
	displayName?: string;
	email?: string;
	passwordHash?: string;
	role: string;
	isActive?: boolean;
	createdAt?: string;
	updatedAt?: string;
	lastLoginAt?: string | null;
	lastLogin?: string | null;
	permissions?: string[];
	/** Author opt-in only; delivery still requires a separate current capability grant. */
	federationEnabled?: boolean;
	totpEnabled?: boolean;
	totpSecretId?: string | null;
	needsOnboarding?: boolean;
	onboardingStep?: number;
	firstLogin?: boolean;

	// GitHub OAuth linking
	githubId?: number | null;
	githubLogin?: string | null;
	githubLinkedAt?: string | null;

	[key: string]: unknown;
}

/**
 * RV15: public projections copy ONLY these fields. Anything else stored on an
 * account record (password hash, TOTP secret material, recovery codes, future
 * credential fields) never reaches a public read, even if a writer adds it.
 */
export const PUBLIC_ADMIN_USER_FIELDS = Object.freeze([
	'id',
	'username',
	'handle',
	'displayName',
	'email',
	'role',
	'isActive',
	'isLocked',
	'createdAt',
	'updatedAt',
	'lastLoginAt',
	'lastLogin',
	'permissions',
	'federationEnabled',
	'totpEnabled',
	'needsOnboarding',
	'onboardingStep',
	'firstLogin',
	'githubId',
	'githubLogin',
	'githubLinkedAt',
	'bio',
	'avatarUrl',
	'bannerUrl',
	'website',
	'location',
	'pronouns',
] as const);

export type PublicAdminUserField = (typeof PUBLIC_ADMIN_USER_FIELDS)[number];

export interface PublicAdminUser {
	id: string;
	username: string;
	handle?: string;
	displayName?: string;
	email?: string;
	role: string;
	isActive?: boolean;
	isLocked?: boolean;
	createdAt?: string;
	updatedAt?: string;
	lastLoginAt?: string | null;
	lastLogin?: string | null;
	permissions?: string[];
	federationEnabled?: boolean;
	totpEnabled?: boolean;
	needsOnboarding?: boolean;
	onboardingStep?: number;
	firstLogin?: boolean;
	githubId?: number | null;
	githubLogin?: string | null;
	githubLinkedAt?: string | null;
	bio?: string;
	avatarUrl?: string;
	bannerUrl?: string;
	website?: string;
	location?: string;
	pronouns?: string;
}

export interface PublicHandleIdentity {
	id: string;
	username: string;
	handle?: string;
	displayName?: string;
	role: string;
	isActive?: boolean;
	createdAt?: string;
	updatedAt?: string;
	bio?: string;
	avatarUrl?: string;
	bannerUrl?: string;
	website?: string;
	location?: string;
	pronouns?: string;
	githubLogin?: string | null;
	githubLinkedAt?: string | null;
}

export interface StoredAdminUserData {
	id?: string;
	username?: string;
	handle?: string;
	displayName?: string;
	email?: string;
	passwordHash?: string;
	role: string;
	isActive?: boolean;
	createdAt?: string;
	updatedAt?: string;
	lastLoginAt?: string | null;
	lastLogin?: string | null;
	permissions?: string[];
	/** Missing values are read as false; only explicit true records author opt-in. */
	federationEnabled?: boolean;
	totpEnabled?: boolean;
	totpSecretId?: string | null;
	needsOnboarding?: boolean;
	onboardingStep?: number;
	firstLogin?: boolean;
	githubId?: number | null;
	githubLogin?: string | null;
	githubLinkedAt?: string | null;
	[key: string]: unknown;
}




export interface CreateUserData {
	handle: string;
	password: string;
	role?: string;
	email?: string;
	totpEnabled?: boolean;
	totpSecretId?: string;
	githubId?: number;
	githubLogin?: string;
}
