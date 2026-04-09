import type { Metadata } from "next";
import { Analytics } from "@vercel/analytics/next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vektor — The Relational Entity Intelligence Platform",
  description:
    "AI-native intelligence for every entity, every relationship, every agent. Across ERP, Financial Services, Healthcare, and Cloud IAM.",
  keywords: [
    "relational entity intelligence",
    "AI agent governance",
    "entity intelligence platform",
    "SOX compliance",
    "SEC FINRA compliance",
    "HIPAA compliance",
    "zero trust",
    "ERP security",
    "financial services security",
    "healthcare access governance",
    "NHI governance",
  ],
  openGraph: {
    title: "Vektor — The Relational Entity Intelligence Platform",
    description:
      "AI-native intelligence for every entity, every relationship, every agent. Across ERP, Financial Services, Healthcare, and Cloud IAM.",
    url: "https://getvektor.ai",
    siteName: "Vektor",
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
