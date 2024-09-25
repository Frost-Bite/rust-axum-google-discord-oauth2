// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  compatibilityDate: '2024-04-03',
  devtools: { enabled: true },
  devServer: {
    port: 3005,
    host: '127.0.0.1'
  },
  modules: [],

  // Configure a proxy
  runtimeConfig: {
    public: {
      apiBase: process.env.API_BASE || 'http://localhost:3000', // Backend URL
    },
  },

  nitro: {
    devProxy: {
      '/api/': {
        target: 'http://localhost:3000', // Your backend URL
        changeOrigin: true,
      },
    },
  },
})
