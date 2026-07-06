// Default (development) environment.
//
// apiBaseUrl is intentionally a *relative* path ('/api') so requests are served
// through the nginx reverse proxy in the deployed stack (see frontend/nginx.conf)
// and through the dev-server proxy locally. Override in environment.prod.ts (or
// via an Angular fileReplacements entry) if the API is hosted on a different
// origin.
export const environment = {
  production: false,
  apiBaseUrl: '/api',
};
