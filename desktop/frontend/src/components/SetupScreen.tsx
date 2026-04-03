import { useState, useEffect } from "react";
import { api } from "../api";
import { friendlyError } from "../errors";
import { useAutoResize } from "../useAutoResize";
import { Input, Alert, StatusText, GlassCard, Logo } from "./ui";
import type { SetupState } from "../types";

interface Props {
  onComplete: () => void;
}

export function SetupScreen({ onComplete }: Props) {
  const contentRef = useAutoResize();
  const [state, setState] = useState<SetupState>("detect");
  const [pin, setPin] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState("");
  const [deviceFound, setDeviceFound] = useState(false);

  useEffect(() => {
    if (state !== "detect") return;
    const interval = setInterval(async () => {
      try {
        const found = await api.detectDevice();
        setDeviceFound(found);
      } catch {
        setDeviceFound(false);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [state]);

  const handleRegister = async () => {
    if (!pin || !label) return;
    setState("waiting_touch");
    try {
      await api.register(pin, label);
      setState("success");
      setTimeout(onComplete, 1000);
    } catch (err) {
      setError(friendlyError(err));
      setState("error");
    }
  };

  return (
    <div ref={contentRef}
         className="gradient-bg flex flex-col items-center justify-center p-8 pt-14 pb-8 select-none"
         style={{ WebkitAppRegion: "drag" } as any}>

      <div className="mb-6">
        {state === "success"
          ? <img src="/checkmark.svg" alt="Success" className="w-16 h-16 opacity-80" />
          : <Logo className="w-24 h-24" />}
      </div>

      <GlassCard style={{ WebkitAppRegion: "no-drag" } as any}>
        <div className="text-center">
          <h1 className="text-lg font-semibold text-text">Welcome to Monban</h1>
          <p className="text-text-secondary text-sm mt-1">Register your security key to get started</p>
        </div>

        {state === "detect" && (
          <div className="space-y-4">
            <div aria-live="polite" className={`text-center text-sm ${deviceFound ? "text-accent font-medium" : "text-text-secondary"}`}>
              {deviceFound ? "Security key detected" : "Insert your security key..."}
            </div>
            {deviceFound && (
              <>
                <Input
                  type="text"
                  label="Key label"
                  placeholder="Key label (e.g. YubiKey 5C, Titan, etc.)"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                />
                <Input
                  type="password"
                  label="Security key PIN"
                  placeholder="Security key PIN"
                  value={pin}
                  onChange={(e) => setPin(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleRegister()}
                />
                <button
                  onClick={handleRegister}
                  disabled={!pin || !label}
                  className="btn-primary"
                >
                  Register
                </button>
              </>
            )}
          </div>
        )}

        {state === "waiting_touch" && (
          <StatusText variant="accent" pulse>Touch your security key...</StatusText>
        )}

        {state === "success" && (
          <StatusText variant="success">Registered successfully</StatusText>
        )}

        {state === "error" && (
          <div className="space-y-4">
            <Alert>{error}</Alert>
            <button
              onClick={() => { setState("detect"); setError(""); setPin(""); }}
              className="btn-secondary"
            >
              Try Again
            </button>
          </div>
        )}
      </GlassCard>
    </div>
  );
}
