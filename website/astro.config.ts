import cloudflare from "@astrojs/cloudflare";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "astro/config";

export default defineConfig({
	adapter: cloudflare(),
	vite: {
		plugins: [tailwindcss()],
	},
});
