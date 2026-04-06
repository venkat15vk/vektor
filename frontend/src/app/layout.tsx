import type { Metadata } from "next";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vektor AI — Identity Intelligence for the Agentic Enterprise",
  description:
    "Map, score, govern, and remediate identity risk across cloud IAM and ERP systems. AI-native. ML-scored. Agent-executed.",
  keywords: [
    "identity intelligence",
    "IAM",
    "identity governance",
    "AI agent governance",
    "SOX compliance",
    "zero trust",
    "ERP security",
  ],
  openGraph: {
    title: "Vektor AI — Identity Intelligence for the Agentic Enterprise",
    description:
      "Map, score, govern, and remediate identity risk across cloud IAM and ERP systems.",
    url: "https://getvektor.ai",
    siteName: "Vektor AI",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
        <Analytics />
      </body>
    </html>
  );
}
