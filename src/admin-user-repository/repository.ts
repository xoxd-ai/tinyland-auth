















import { promises as fs } from 'fs';
import * as bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { basename, dirname, join } from 'path';
import { getConfig } from './config.js';
import { PUBLIC_ADMIN_USER_FIELDS } from './types.js';
import type {
	AdminUser,
	CreateUserData,
	PublicAdminUser,
	PublicHandleIdentity,
	StoredAdminUserData,
} from './types.js';

export class AdminUserRepository {
	private cache: Map<string, { user: AdminUser; timestamp: number }> = new Map();

	/** RV15: explicit allowlist, never a denylist of known secret fields. */
	private sanitizeUser<T extends AdminUser>(user: T): PublicAdminUser {
		const record = user as Record<string, unknown>;
		const sanitized: Record<string, unknown> = {};
		for (const field of PUBLIC_ADMIN_USER_FIELDS) {
			if (Object.hasOwn(record, field) && record[field] !== undefined) {
				sanitized[field] = record[field];
			}
		}
		return sanitized as unknown as PublicAdminUser;
	}

	private sanitizePublicHandleIdentity<T extends AdminUser>(user: T): PublicHandleIdentity {
		return {
			id: user.id,
			username: user.username,
			handle: user.handle,
			displayName: user.displayName,
			role: user.role,
			isActive: user.isActive,
			createdAt: user.createdAt,
			updatedAt: user.updatedAt,
			bio: user.bio as string | undefined,
			avatarUrl: user.avatarUrl as string | undefined,
			bannerUrl: user.bannerUrl as string | undefined,
			website: user.website as string | undefined,
			location: user.location as string | undefined,
			pronouns: user.pronouns as string | undefined,
			githubLogin: user.githubLogin ?? null,
			githubLinkedAt: user.githubLinkedAt ?? null,
		};
	}

	


	private async readUsers(): Promise<AdminUser[]> {
		const { usersFilePath } = getConfig();
		try {
			const content = await fs.readFile(usersFilePath, 'utf8');
			const data = JSON.parse(content);

			
			const users: AdminUser[] = Array.isArray(data) ? data : (data.users || []);
			return users.map((user) => ({
				...user,
				federationEnabled: user.federationEnabled === true,
			}));
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
				
				return [];
			}
			throw error;
		}
	}

	


	private async writeUsers(users: AdminUser[]): Promise<void> {
		// Durable replacement only; callers still own serialization of read/modify/write.
		const { usersFilePath, filePermissions } = getConfig();
		const directory = dirname(usersFilePath);
		const temporaryPath = join(directory, `.${basename(usersFilePath)}.${crypto.randomBytes(16).toString('hex')}.tmp`);
		let file: Awaited<ReturnType<typeof fs.open>> | undefined;
		let parent: Awaited<ReturnType<typeof fs.open>> | undefined;
		let ownsTemporary = false;
		let replaced = false;
		try {
			file = await fs.open(temporaryPath, 'wx', 0o600);
			ownsTemporary = true;
			await fs.writeFile(file, JSON.stringify(users, null, 2), 'utf8');
			await file.sync();
			await fs.rename(temporaryPath, usersFilePath);
			replaced = true;
			try {
				await file.chmod(filePermissions);
			} catch {
				console.warn('[AdminUserRepository] Failed to set file permissions');
			}
			await file.sync();
			await file.close();
			file = undefined;
			parent = await fs.open(directory, 'r');
			await parent.sync();
			await parent.close();
			parent = undefined;
		} finally {
			// A rename followed by an fsync failure is uncertain, never a successful write.
			this.cache.clear();
			await file?.close().catch(() => {});
			await parent?.close().catch(() => {});
			if (ownsTemporary && !replaced) {
				await fs.unlink(temporaryPath).catch(() => {});
			}
		}
	}

	


	async findByHandle(handle: string): Promise<AdminUser | null> {
		const { cacheTtl } = getConfig();

		
		const cached = this.cache.get(`handle:${handle}`);
		if (cached && Date.now() - cached.timestamp < cacheTtl) {
			return cached.user;
		}

		const users = await this.readUsers();
		const user = users.find((u: AdminUser) =>
			(u.handle === handle || u.username === handle) && u.isActive !== false
		);

		
		if (user) {
			this.cache.set(`handle:${handle}`, { user, timestamp: Date.now() });
		}

		return user || null;
	}

	async findByHandlePublic(handle: string): Promise<PublicAdminUser | null> {
		const user = await this.findByHandle(handle);
		return user ? this.sanitizeUser(user) : null;
	}

	async findPublicHandleIdentity(handle: string): Promise<PublicHandleIdentity | null> {
		const user = await this.findByHandle(handle);
		return user ? this.sanitizePublicHandleIdentity(user) : null;
	}

	


	async findById(id: string): Promise<AdminUser | null> {
		const { cacheTtl } = getConfig();

		
		const cached = this.cache.get(`id:${id}`);
		if (cached && Date.now() - cached.timestamp < cacheTtl) {
			return cached.user;
		}

		const users = await this.readUsers();
		const user = users.find((u: AdminUser) => u.id === id);

		
		if (user) {
			this.cache.set(`id:${id}`, { user, timestamp: Date.now() });
		}

		return user || null;
	}

	async findByIdPublic(id: string): Promise<PublicAdminUser | null> {
		const user = await this.findById(id);
		return user ? this.sanitizeUser(user) : null;
	}

	


	async findByGitHubId(githubId: number): Promise<AdminUser | null> {
		const users = await this.readUsers();
		return users.find((u: AdminUser) =>
			u.githubId === githubId && u.isActive !== false
		) || null;
	}

	async linkGitHub(userId: string, githubId: number, githubLogin: string): Promise<AdminUser> {
		const existing = await this.findByGitHubId(githubId);
		if (existing && existing.id !== userId) {
			throw new Error(`GitHub account ${githubLogin} is already linked to another admin user`);
		}
		return this.update(userId, {
			githubId,
			githubLogin,
			githubLinkedAt: new Date().toISOString(),
		});
	}

	async unlinkGitHub(userId: string): Promise<AdminUser> {
		return this.update(userId, {
			githubId: null,
			githubLogin: null,
			githubLinkedAt: null,
		});
	}

	async findByEmail(email: string): Promise<AdminUser | null> {
		const users = await this.readUsers();
		return users.find((u: AdminUser) =>
			u.username === email && u.isActive !== false
		) || null;
	}

	async findByEmailPublic(email: string): Promise<PublicAdminUser | null> {
		const user = await this.findByEmail(email);
		return user ? this.sanitizeUser(user) : null;
	}

	


	async findAll(): Promise<AdminUser[]> {
		return await this.readUsers();
	}

	async findAllPublic(): Promise<PublicAdminUser[]> {
		const users = await this.findAll();
		return users.map((user) => this.sanitizeUser(user));
	}

	async findAllPublicHandleIdentities(): Promise<PublicHandleIdentity[]> {
		const users = await this.findAll();
		return users
			.filter((user) => user.isActive !== false)
			.map((user) => this.sanitizePublicHandleIdentity(user));
	}

	


	async create(userData: CreateUserData): Promise<AdminUser> {
		const { saltRounds } = getConfig();
		const users = await this.readUsers();

		
		const exists = users.some((u: AdminUser) =>
			u.handle === userData.handle || u.username === userData.handle
		);

		if (exists) {
			throw new Error(`User with handle '${userData.handle}' already exists`);
		}

		
		const passwordHash = await bcrypt.hash(userData.password, saltRounds);

		
		const newUser: AdminUser = {
			id: crypto.randomUUID(),
			username: userData.handle,
			handle: userData.handle,
			passwordHash,
			role: userData.role || 'admin',
			isActive: true,
			createdAt: new Date().toISOString(),
			updatedAt: new Date().toISOString(),
			lastLoginAt: null,
			permissions: [],
			federationEnabled: false,
			totpEnabled: userData.totpEnabled || false,
			totpSecretId: userData.totpSecretId || null,
			needsOnboarding: false,
			onboardingStep: 0,
			firstLogin: false,
			githubId: userData.githubId || null,
			githubLogin: userData.githubLogin || null,
			githubLinkedAt: userData.githubId ? new Date().toISOString() : null,
		};

		users.push(newUser);
		await this.writeUsers(users);

		return newUser;
	}

	async createStoredUser(userData: StoredAdminUserData): Promise<AdminUser> {
		const users = await this.readUsers();
		const handle = userData.handle ?? userData.username;

		if (!handle) {
			throw new Error('Stored admin user must include a handle or username');
		}

		const exists = users.some((u: AdminUser) =>
			u.handle === handle || u.username === handle
		);

		if (exists) {
			throw new Error(`User with handle '${handle}' already exists`);
		}

		const timestamp = new Date().toISOString();
		const newUser: AdminUser = {
			id: userData.id ?? crypto.randomUUID(),
			username: userData.username ?? handle,
			handle,
			displayName: userData.displayName,
			email: userData.email,
			passwordHash: userData.passwordHash,
			role: userData.role,
			isActive: userData.isActive ?? true,
			createdAt: userData.createdAt ?? timestamp,
			updatedAt: userData.updatedAt ?? timestamp,
			lastLoginAt: userData.lastLoginAt ?? null,
			lastLogin: userData.lastLogin ?? null,
			permissions: userData.permissions ?? [],
			federationEnabled: userData.federationEnabled === true,
			totpEnabled: userData.totpEnabled ?? false,
			totpSecretId: userData.totpSecretId ?? null,
			needsOnboarding: userData.needsOnboarding ?? false,
			onboardingStep: userData.onboardingStep ?? 0,
			firstLogin: userData.firstLogin ?? false,
			githubId: userData.githubId ?? null,
			githubLogin: userData.githubLogin ?? null,
			githubLinkedAt: userData.githubLinkedAt ?? null,
		};

		users.push(newUser);
		await this.writeUsers(users);

		return newUser;
	}

	


	async update(id: string, updates: Partial<AdminUser>): Promise<AdminUser> {
		const users = await this.readUsers();
		const index = users.findIndex((u: AdminUser) => u.id === id);

		if (index === -1) {
			throw new Error(`User with id '${id}' not found`);
		}

		
		users[index] = {
			...users[index],
			...updates,
			updatedAt: new Date().toISOString(),
		};
		users[index].federationEnabled = users[index].federationEnabled === true;

		await this.writeUsers(users);

		return users[index];
	}

	


	async delete(id: string): Promise<void> {
		await this.update(id, { isActive: false });
	}

	async deletePermanently(id: string): Promise<boolean> {
		const users = await this.readUsers();
		const index = users.findIndex((u: AdminUser) => u.id === id);

		if (index === -1) {
			return false;
		}

		users.splice(index, 1);
		await this.writeUsers(users);
		return true;
	}

	


	async verifyPassword(handle: string, password: string): Promise<AdminUser | null> {
		const user = await this.findByHandle(handle);

		if (!user || !user.passwordHash) {
			return null;
		}

		const isValid = await bcrypt.compare(password, user.passwordHash);
		return isValid ? user : null;
	}

	


	async updatePassword(id: string, newPassword: string): Promise<void> {
		const { saltRounds } = getConfig();
		const passwordHash = await bcrypt.hash(newPassword, saltRounds);
		await this.update(id, { passwordHash });
	}

	


	async enableTotp(id: string, secretId: string): Promise<void> {
		await this.update(id, {
			totpEnabled: true,
			totpSecretId: secretId,
		});
	}

	


	async disableTotp(id: string): Promise<void> {
		await this.update(id, {
			totpEnabled: false,
			totpSecretId: null,
		});
	}

	


	async hasAnyUsers(): Promise<boolean> {
		const users = await this.readUsers();
		return users.length > 0;
	}

	


	async updateLastLogin(id: string): Promise<void> {
		await this.update(id, {
			lastLoginAt: new Date().toISOString(),
		});
	}

	


	async needsFirstLoginSetup(id: string): Promise<boolean> {
		const user = await this.findById(id);
		if (!user) return false;

		return user.firstLogin === true;
	}

	


	clearCache(): void {
		this.cache.clear();
	}
}


export const adminUserRepository = new AdminUserRepository();
