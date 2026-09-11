/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string;
  readonly VITE_WS_URL: string;
  readonly VITE_AUTH_ENABLED: string;
  readonly VITE_LOCAL_AUTH_ENABLED: string;
  readonly VITE_DEMO_MODE: string;
  readonly VITE_SSO_ENABLED: string;
  readonly VITE_SHOW_SSO_BUTTON: string;
  readonly VITE_KEYCLOAK_URL: string;
  readonly VITE_KEYCLOAK_REALM: string;
  readonly VITE_KEYCLOAK_CLIENT_ID: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
