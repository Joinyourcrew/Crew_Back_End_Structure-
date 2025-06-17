import { defineConfig } from 'vite';

export default defineConfig({
  root: '.', // Set the root to the project directory
  publicDir: 'public', // Specify the public directory
  server: {
    open: true, // Automatically open the browser
  },
});
