import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
    build: {
        lib: {
            entry: resolve(__dirname, 'django_fido/js/fido2.js'),
            name: 'fido2',
            fileName: () => 'fido2.js',
        },
        outDir: resolve(__dirname, 'django_fido/static/django_fido/js'),
        sourcemap: true,
        rollupOptions: {
            output: {
                entryFileNames: 'fido2.js',
                sourcemapFileNames: 'fido2.js.map',
            },
        },
    },
})
