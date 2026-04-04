import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

import cloudflare from "@astrojs/cloudflare";

export default defineConfig({
  vite: {
      plugins: [tailwindcss()],
	},

  adapter: cloudflare(),
});