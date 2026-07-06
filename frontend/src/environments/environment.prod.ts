// Production environment.
//
// Keeps the relative '/api' base so the built app talks to the API through the
// nginx reverse proxy that fronts it. Point apiBaseUrl at an absolute origin
// (e.g. 'https://api.example.com/api') only if the API is served from a
// different host than the frontend.
export const environment = {
  production: true,
  apiBaseUrl: '/api',
};
