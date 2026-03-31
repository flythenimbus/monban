import { useState, useEffect } from "react";
import { Events } from "@wailsio/runtime";
import { api } from "./api";
import { SetupScreen } from "./components/SetupScreen";
import { LockScreen } from "./components/LockScreen";
import { AdminPanel } from "./components/AdminPanel";

type View = "loading" | "setup" | "lock" | "admin";

function App() {
  const [view, setView] = useState<View>("loading");

  useEffect(() => {
    checkState();
    const off = Events.On("app:locked", () => setView("lock"));
    return off;
  }, []);

  const checkState = async () => {
    try {
      const status = await api.getStatus();
      if (!status.registered) {
        setView("setup");
      } else if (status.locked) {
        setView("lock");
      } else {
        setView("admin");
      }
    } catch {
      setView("setup");
    }
  };

  switch (view) {
    case "loading":
      return (
        <div className="gradient-bg flex items-center justify-center min-h-screen text-text-secondary">
          Loading...
        </div>
      );
    case "setup":
      return <SetupScreen onComplete={() => { api.exitFullscreen(); setView("admin"); }} />;
    case "lock":
      return <LockScreen onUnlock={() => { api.exitFullscreen(); setView("admin"); }} />;
    case "admin":
      return <AdminPanel />;
  }
}

export default App;
