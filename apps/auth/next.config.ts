import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Logowanie działa w całości na AWS (ADR-0062): jeden katalog z serwerem i zależnościami do kontenera
  output: "standalone",
  // Sterowniki bazy i poczty zostają w node_modules, poza paczką serwera
  serverExternalPackages: ["@prisma/client", "@prisma/adapter-pg", "pg", "nodemailer"],
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
