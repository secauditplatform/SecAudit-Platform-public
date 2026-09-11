import type { ReactNode } from "react";

type IconProps = { className?: string };

function StrokeIcon({ className, children }: IconProps & { children: ReactNode }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {children}
    </svg>
  );
}

export function IconDashboard({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <rect width="7" height="9" x="3" y="3" rx="1" />
      <rect width="7" height="5" x="14" y="3" rx="1" />
      <rect width="7" height="9" x="14" y="12" rx="1" />
      <rect width="7" height="5" x="3" y="16" rx="1" />
    </StrokeIcon>
  );
}

export function IconPlatformOverview({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M12 2 2 7l10 5 10-5-10-5z" />
      <path d="m2 17 10 5 10-5" />
      <path d="m2 12 10 5 10-5" />
    </StrokeIcon>
  );
}

export function IconTemplates({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <rect width="7" height="7" x="3" y="3" rx="1" />
      <rect width="7" height="7" x="3" y="14" rx="1" />
      <path d="M14 4h7" />
      <path d="M14 9h7" />
      <path d="M14 15h7" />
      <path d="M14 20h7" />
    </StrokeIcon>
  );
}

export function IconHosts({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <rect width="20" height="8" x="2" y="2" rx="2" />
      <rect width="20" height="8" x="2" y="14" rx="2" />
      <line x1="6" x2="6.01" y1="6" y2="6" />
      <line x1="6" x2="6.01" y1="18" y2="18" />
    </StrokeIcon>
  );
}

export function IconJobs({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <rect width="8" height="4" x="8" y="2" rx="1" />
      <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
      <path d="M8 11h.01" />
      <path d="M12 11h4" />
      <path d="M8 16h.01" />
      <path d="M12 16h4" />
    </StrokeIcon>
  );
}

export function IconRemediation({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
    </StrokeIcon>
  );
}

export function IconReports({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z" />
      <path d="M14 2v4a2 2 0 0 0 2 2h4" />
      <path d="M8 13h2" />
      <path d="M8 17h2" />
      <path d="M14 13v4" />
      <path d="M17 17v-1" />
    </StrokeIcon>
  );
}

export function IconTrends({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <polyline points="22 7 13.5 15.5 8.5 10.5 2 17" />
      <polyline points="16 7 22 7 22 13" />
    </StrokeIcon>
  );
}

export function IconAudit({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M2 6h4" />
      <path d="M2 10h4" />
      <path d="M2 14h4" />
      <path d="M2 18h4" />
      <rect width="16" height="20" x="4" y="2" rx="2" />
      <path d="M9.5 8h5" />
      <path d="M9.5 12H16" />
      <path d="M9.5 16H14" />
    </StrokeIcon>
  );
}

export function IconAuditFlow({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M3 7V5a2 2 0 0 1 2-2h2" />
      <path d="M17 3h2a2 2 0 0 1 2 2v2" />
      <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
      <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
      <circle cx="12" cy="12" r="3" />
    </StrokeIcon>
  );
}

export function IconWaivers({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z" />
      <path d="M14 2v4a2 2 0 0 0 2 2h4" />
      <path d="M9 15h6" />
    </StrokeIcon>
  );
}

export function IconCredentials({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <rect width="20" height="14" x="2" y="5" rx="2" />
      <circle cx="8.5" cy="12" r="2.25" />
      <path d="M13 10.5h6" />
      <path d="M13 13.5h4" />
    </StrokeIcon>
  );
}

export function IconPlaybook({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M12 7v14" />
      <path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z" />
    </StrokeIcon>
  );
}

export function IconConsole({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" x2="20" y1="19" y2="19" />
    </StrokeIcon>
  );
}

export function IconUsers({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </StrokeIcon>
  );
}

export function IconBell({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M10.268 21a2 2 0 0 0 3.464 0" />
      <path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326" />
    </svg>
  );
}

export function IconSettings({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 512 512" fill="currentColor" aria-hidden>
      <path d="M487.4 315.7l-42.6-24.6c4.3-23.2 4.3-47.1 0-70.3l42.6-24.6c12.9-7.5 17.4-24.1 10.3-37.1L453 78.3c-7.2-13-23.9-17.8-37.1-10.3l-42.6 24.6c-18.1-15.4-39.1-27.1-62.1-34.6V24.5C310.1 10.9 299.2 0 286 0H226c-13.2 0-24.1 10.9-22.2 24.5v41.2c-23 7.5-44 19.2-62.1 34.6L99.1 75.5c-13.2-7.5-29.9-2.7-37.1 10.3L14.6 183.5c-7.1 13-.6 29.6 10.3 37.1l42.6 24.6c-4.3 23.2-4.3 47.1 0 70.3l-42.6 24.6c-12.9 7.5-17.4 24.1-10.3 37.1l42.6 73.8c7.2 13 23.9 17.8 37.1 10.3l42.6-24.6c18.1 15.4 39.1 27.1 62.1 34.6v41.2c1.9 13.6 12.9 24.5 26.2 24.5h60c13.2 0 24.1-10.9 22.2-24.5v-41.2c23-7.5 44-19.2 62.1-34.6l42.6 24.6c13.2 7.5 29.9 2.7 37.1-10.3l42.6-73.8c7.1-13 .6-29.6-10.3-37.1zM256 336c-44.2 0-80-35.8-80-80s35.8-80 80-80 80 35.8 80 80-35.8 80-80 80z" />
    </svg>
  );
}

export function IconSun({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </StrokeIcon>
  );
}

export function IconMoon({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </StrokeIcon>
  );
}

export function IconDisplay({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <rect width="20" height="14" x="2" y="3" rx="2" />
      <path d="M8 21h8" />
      <path d="M12 17v4" />
    </StrokeIcon>
  );
}

export function IconCheck({ className }: IconProps) {
  return (
    <StrokeIcon className={className}>
      <path d="M20 6 9 17l-5-5" />
    </StrokeIcon>
  );
}

export function IconSearch({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 512 512" fill="currentColor" aria-hidden>
      <path d="M505 442.7L405.3 343c-4.5-4.5-10.6-7-17-7H372c27.6-35.3 44-79.7 44-128C416 93.1 322.9 0 208 0S0 93.1 0 208s93.1 208 208 208c48.3 0 92.7-16.4 128-44v16.3c0 6.4 2.5 12.5 7 17l99.7 99.7c9.4 9.4 24.6 9.4 33.9 0l28.3-28.3c9.4-9.4 9.4-24.6.1-34zM208 336c-70.7 0-128-57.2-128-128 0-70.7 57.2-128 128-128 70.7 0 128 57.2 128 128 0 70.7-57.2 128-128 128z" />
    </svg>
  );
}

export function IconBars({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 448 512" fill="currentColor" aria-hidden>
      <path d="M16 132h416c8.8 0 16-7.2 16-16s-7.2-16-16-16H16C7.2 100 0 107.2 0 116s7.2 16 16 16zm0 160h416c8.8 0 16-7.2 16-16s-7.2-16-16-16H16c-8.8 0-16 7.2-16 16s7.2 16 16 16zm0 160h416c8.8 0 16-7.2 16-16s-7.2-16-16-16H16c-8.8 0-16 7.2-16 16s7.2 16 16 16z" />
    </svg>
  );
}

export function IconUpload({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 512 512" fill="currentColor" aria-hidden>
      <path d="M296 384h-80c-13.3 0-24-10.7-24-24V192h-87.7c-17.8 0-26.7-21.5-14.1-34.1L242.3 5.7c7.5-7.5 19.8-7.5 27.3 0l152.2 152.2c12.6 12.6 3.7 34.1-14.1 34.1H320v168c0 13.3-10.7 24-24 24zm216-8v112c0 13.3-10.7 24-24 24H24c-13.3 0-24-10.7-24-24V376c0-13.3 10.7-24 24-24h136v-80c0-55.6 45-100 100-100s100 45 100 100v80h136c13.3 0 24 10.7 24 24z" />
    </svg>
  );
}

export function IconTrash({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="m3 6 2 0 16 0" />
      <path d="M8 6V4.5A1.5 1.5 0 0 1 9.5 3h5A1.5 1.5 0 0 1 16 4.5V6m2 0v13.5A1.5 1.5 0 0 1 16.5 21h-9A1.5 1.5 0 0 1 6 19.5V6" />
      <path d="M10 11v5M14 11v5" />
    </svg>
  );
}

export function IconRefresh({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M21 12a9 9 0 1 1-2.6-6.3" />
      <path d="M21 3v6h-6" />
    </svg>
  );
}

export function IconEye({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M2.036 12.322a1.012 1.012 0 0 1 0-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.964-7.178Z" />
      <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
    </svg>
  );
}

export function IconEyeSlash({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M3.98 8.223A10.477 10.477 0 0 0 1.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.451 10.451 0 0 1 12 4.5c4.756 0 8.773 3.162 10.065 7.498a10.522 10.522 0 0 1-4.293 5.774M6.228 6.228 3 3m3.228 3.228 3.65 3.65m7.894 7.894L21 21m-3.228-3.228-3.65-3.65m0 0a3 3 0 1 0-4.243-4.243m4.242 4.242L9.88 9.88" />
    </svg>
  );
}

export function IconLoginSso({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M9 12.75 11.25 15 15 9.75" />
      <path d="M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 0 1-1.043 3.296 3.745 3.745 0 0 1-3.296 1.043A3.745 3.745 0 0 1 12 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 0 1-3.296-1.043 3.745 3.745 0 0 1-1.043-3.296A3.745 3.745 0 0 1 3 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 0 1 1.043-3.296 3.746 3.746 0 0 1 3.296-1.043A3.746 3.746 0 0 1 12 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 0 1 3.296 1.043 3.746 3.746 0 0 1 1.043 3.296A3.745 3.745 0 0 1 21 12Z" />
    </svg>
  );
}

export function IconLoginLocal({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />
      <path d="M4.5 20.118a7.5 7.5 0 0 1 15 0A17.933 17.933 0 0 1 12 21.75a17.93 17.93 0 0 1-7.5-1.632Z" />
    </svg>
  );
}

export function IconUserRound({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <circle cx="12" cy="8" r="3.25" />
      <path d="M6.75 19.25c0-2.9 2.35-5.25 5.25-5.25s5.25 2.35 5.25 5.25" />
    </svg>
  );
}

export function IconKeyRound({ className }: IconProps) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <path d="M7 11V8a5 5 0 0 1 10 0v3" />
      <rect x="5" y="11" width="14" height="10" rx="2" />
    </svg>
  );
}

export function IconAnsible({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 512 512" fill="currentColor" aria-hidden>
      <path d="M256 8C119 8 8 119 8 256s111 248 248 248 248-111 248-248S393 8 256 8zm121.6 313.1c4.7 4.7 4.7 12.3 0 17L338 377.6c-4.7 4.7-12.3 4.7-17 0L256 312l-65.1 65.6c-4.7 4.7-12.3 4.7-17 0L134.4 338c-4.7-4.7-4.7-12.3 0-17l65.6-65-65.6-65.1c-4.7-4.7-4.7-12.3 0-17l39.6-39.6c4.7-4.7 12.3-4.7 17 0l65 65.7 65.1-65.6c4.7-4.7 12.3-4.7 17 0l39.6 39.6c4.7 4.7 4.7 12.3 0 17L312 256l65.6 65.1z" />
    </svg>
  );
}

export function IconLinux({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 32 32" aria-hidden>
      <ellipse cx="9.5" cy="28.5" rx="5.5" ry="2.6" fill="#F0AB00" />
      <ellipse cx="22.5" cy="28.5" rx="5.5" ry="2.6" fill="#F0AB00" />
      <path
        fill="#141414"
        d="M16 2.8c-4.6 0-8.3 3.6-8.3 8.4 0 2.1.9 4 2.3 5.3-1 .8-1.8 2-2.1 3.4l-.55 2.3c-.25 1.05.45 2.05 1.55 2.25l.75.15-.25 1.35c-.1.55.35 1.05.95 1.05h2.6c.6 0 1.05-.5.95-1.05l-.25-1.35.75-.15c1.1-.2 1.8-1.2 1.55-2.25l-.55-2.3c-.3-1.35-1.1-2.55-2.1-3.35 1.4-1.35 2.3-3.25 2.3-5.45C24.3 6.4 20.6 2.8 16 2.8z"
      />
      <path
        fill="#2B2B2B"
        d="M16 4.5c-3.6 0-6.5 2.8-6.5 6.5 0 1.5.6 2.9 1.6 3.9-.8.6-1.4 1.5-1.6 2.6l-.4 1.7c-.15.75.35 1.45 1.15 1.6l.55.1-.15.9c-.05.45.3.85.8.85h1.9c.5 0 .85-.4.8-.85l-.15-.9.55-.1c.8-.15 1.3-.85 1.15-1.6l-.4-1.7c-.2-1.1-.8-2-1.6-2.6 1-1 1.6-2.4 1.6-3.9 0-3.7-2.9-6.5-6.5-6.5z"
        opacity="0.55"
      />
      <ellipse cx="16" cy="18.8" rx="6.8" ry="8.2" fill="#FFFFFF" />
      <ellipse cx="11.4" cy="10.2" rx="2.9" ry="3.5" fill="#FFFFFF" />
      <ellipse cx="20.6" cy="10.2" rx="2.9" ry="3.5" fill="#FFFFFF" />
      <circle cx="11.9" cy="10.8" r="1.15" fill="#141414" />
      <circle cx="20.1" cy="10.8" r="1.15" fill="#141414" />
      <circle cx="12.35" cy="10.35" r="0.38" fill="#FFFFFF" />
      <circle cx="20.55" cy="10.35" r="0.38" fill="#FFFFFF" />
      <path fill="#F0AB00" d="M16 12.1 12.8 15.2h6.4L16 12.1z" />
    </svg>
  );
}

export function IconWindows({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M3 5.5 10.5 4.3v7.4H3V5.5Zm0 8.5h7.5v7.4L3 19.6V14Zm9.5-9.9L21 3.1v8.6h-8.5V4.1Zm0 9.9H21V21l-8.5-1.5V14Z" />
    </svg>
  );
}

export function IconNetwork({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <rect x="3" y="14" width="6" height="5" rx="1" />
      <rect x="15" y="14" width="6" height="5" rx="1" />
      <rect x="9" y="5" width="6" height="5" rx="1" />
      <path d="M6 14V11h3M15 11h3v3M12 10V8" />
    </svg>
  );
}

/** Network topology with shield — compliance checks on device configs. */
export function IconNetworkCompliance({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <rect x="2" y="13" width="5" height="4" rx="0.75" />
      <rect x="17" y="13" width="5" height="4" rx="0.75" />
      <rect x="9.5" y="4" width="5" height="4" rx="0.75" />
      <path d="M4.5 13V10.5h2M19.5 10.5V13M12 8.5V6.5" />
      <path
        d="M12 16.5c-2.2 0-4 .9-4 2v1.5h8V18.5c0-1.1-1.8-2-4-2z"
        strokeLinejoin="round"
      />
      <path d="M12 15.5V17.5M10.2 19.2 12 21l1.8-1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Network topology with wrench — remediation config generation. */
export function IconNetworkRemediation({ className }: IconProps) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden>
      <rect x="1.5" y="12" width="5" height="4" rx="0.75" />
      <rect x="17.5" y="12" width="5" height="4" rx="0.75" />
      <rect x="9" y="3" width="5" height="4" rx="0.75" />
      <path d="M4 12V9.5h2M20 9.5V12M11.5 7V5" />
      <path
        d="M14.5 16.5 18 20l-1.2 1.2a1.1 1.1 0 0 1-1.6 0l-1.1-1.1a1.1 1.1 0 0 1 0-1.6L15.5 17"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M13.5 17.5 11 20" strokeLinecap="round" />
    </svg>
  );
}
