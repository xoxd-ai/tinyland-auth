export interface AdminUserRepositoryConfig {
	
	usersFilePath?: string;
	
	cacheTtl?: number;
	
	saltRounds?: number;
	
	filePermissions?: number;
}

let config: AdminUserRepositoryConfig = {};









export function configure(c: AdminUserRepositoryConfig): void {
	config = { ...config, ...c };
}






export function getConfig(): Required<AdminUserRepositoryConfig> {
	return {
		usersFilePath: config.usersFilePath ?? process.cwd() + '/content/auth/admin-users.json',
		cacheTtl: config.cacheTtl ?? 5000,
		saltRounds: config.saltRounds ?? 10,
		filePermissions: config.filePermissions ?? 0o600,
	};
}





export function resetConfig(): void {
	config = {};
}
