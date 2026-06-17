import { provideModrinthClient } from '@modrinth/ui'

import { createModrinthClient } from '~/helpers/api.ts'

export function setupModrinthClientProvider(auth: Awaited<ReturnType<typeof useAuth>>) {
	const config = useRuntimeConfig()
	const client = createModrinthClient(auth, {
		apiBaseUrl: config.public.apiBaseUrl.replace('/v2/', '/'),
		archonBaseUrl: (config.public.pyroBaseUrl || 'http://localhost:8000').replace('/v2/', '/'),
		rateLimitKey: config.rateLimitKey,
	})
	provideModrinthClient(client)
	return client
}
