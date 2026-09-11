import { Link } from "react-router-dom";

type StatTileProps = {
  label: string;
  value: string | number;
  variant?: "default" | "success" | "danger" | "warning" | "info";
  sublabel?: string;
  to?: string;
};

export function StatTile({ label, value, variant = "default", sublabel, to }: StatTileProps) {
  const className = `pf-stat-tile pf-stat-tile--${variant}${to ? " pf-stat-tile--link" : ""}`;
  const content = (
    <>
      <div className="pf-stat-tile__value">{value}</div>
      <div className="pf-stat-tile__label">{label}</div>
      {sublabel && <div className="pf-stat-tile__sublabel">{sublabel}</div>}
    </>
  );

  if (to) {
    return (
      <Link to={to} className={className}>
        {content}
      </Link>
    );
  }

  return <div className={className}>{content}</div>;
}
