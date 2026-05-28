import { useEffect, useLayoutEffect, useState } from "react";
import { getStoredUser, isAuthenticated, logout, setPublicScanAccess } from "./api/client";
import ScanStatusView from "./components/ScanStatus";
import ScanHistory from "./components/ScanHistory";
import AgentDownload from "./components/AgentDownload";
import NewScanForm from "./components/NewScanForm";
import LoginPage from "./components/LoginPage";
import RegisterPage from "./components/RegisterPage";
import UserManagement from "./components/UserManagement";
import AdminCheckerDashboard from "./components/AdminCheckerDashboard";
import CheckerCatalogPage from "./components/CheckerCatalogPage";
import type { User } from "./types";

type Page = "history" | "newScan" | "scanning" | "agent" | "users" | "checkerDashboard" | "checkerCatalog";
type AuthPage = "login" | "register";

function parsePublicScanAccess(): { scanId: string; token: string } | null {
  const hash = window.location.hash || "";
  const match = hash.match(/^#\/public-scan\/([^?]+)(?:\?(.*))?$/);
  if (!match) return null;
  const scanId = decodeURIComponent(match[1] || "");
  const params = new URLSearchParams(match[2] || "");
  const token = params.get("token") || "";
  if (!scanId || !token) return null;
  return { scanId, token };
}

export default function App() {
  const [user, setUser] = useState<User | null>(getStoredUser);
  const [page, setPage] = useState<Page>("history");
  const [authPage, setAuthPage] = useState<AuthPage>("login");
  const [scanId, setScanId] = useState<string>("");
  const [publicAccess, setPublicAccess] = useState<{ scanId: string; token: string } | null>(
    parsePublicScanAccess,
  );

  useEffect(() => {
    const handleExpired = () => setUser(null);
    window.addEventListener("auth_expired", handleExpired);
    return () => window.removeEventListener("auth_expired", handleExpired);
  }, []);

  useEffect(() => {
    const syncPublicAccess = () => setPublicAccess(parsePublicScanAccess());
    window.addEventListener("hashchange", syncPublicAccess);
    return () => window.removeEventListener("hashchange", syncPublicAccess);
  }, []);

  useLayoutEffect(() => {
    setPublicScanAccess(publicAccess);
    return () => setPublicScanAccess(null);
  }, [publicAccess]);

  const handleLogin = (u: User) => {
    setUser(u);
    setPage("history");
  };

  const handleLogout = () => {
    logout();
    setUser(null);
  };

  if (publicAccess) {
    return (
      <ScanStatusView
        scanId={publicAccess.scanId}
        onBack={() => {
          window.location.hash = "";
          setPublicAccess(null);
        }}
      />
    );
  }

  if (!user || !isAuthenticated()) {
    if (authPage === "register") {
      return <RegisterPage onRegister={handleLogin} onGoLogin={() => setAuthPage("login")} />;
    }
    return <LoginPage onLogin={handleLogin} onGoRegister={() => setAuthPage("register")} />;
  }

  const handleViewScan = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleScanStarted = (id: string) => {
    setScanId(id);
    setPage("scanning");
  };

  const handleBack = () => {
    setPage("history");
  };

  return (
    <>
      {page === "history" && (
        <ScanHistory
          onViewScan={handleViewScan}
          onDownloadAgent={() => setPage("agent")}
          onNewScan={() => setPage("newScan")}
          user={user}
          onLogout={handleLogout}
          onManageUsers={() => setPage("users")}
          onCheckerDashboard={() => setPage("checkerDashboard")}
          onCheckerCatalog={() => setPage("checkerCatalog")}
        />
      )}
      {page === "newScan" && (
        <NewScanForm onScanStarted={handleScanStarted} onBack={handleBack} />
      )}
      {page === "scanning" && (
        <ScanStatusView scanId={scanId} onBack={handleBack} />
      )}
      {page === "agent" && (
        <AgentDownload onBack={handleBack} />
      )}
      {page === "users" && (
        <UserManagement onBack={handleBack} user={user} />
      )}
      {page === "checkerDashboard" && (
        <AdminCheckerDashboard onBack={handleBack} onViewScan={handleViewScan} />
      )}
      {page === "checkerCatalog" && (
        <CheckerCatalogPage onBack={handleBack} />
      )}
    </>
  );
}
