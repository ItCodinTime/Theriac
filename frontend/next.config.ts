import type { NextConfig } from "next";
import path from "path";

// Proxy REST calls to the FastAPI backend server-side. This lets the HTTPS
// Vercel deployment talk to an http:// backend without browser mixed-content
// blocking or CORS, and works the same in local dev.
const backend = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  // Pin the workspace root to this app. Without this, a stray lockfile in a
  // parent directory can make Next infer the wrong root and break bundling.
  turbopack: {
    root: path.join(__dirname),
  },
  async rewrites() {
    return [
      {
        source: "/backend/:path*",
        destination: `${backend}/:path*`,
      },
    ];
  },
};

export default nextConfig;
