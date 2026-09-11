export type ScheduleFrequency = "hourly" | "daily" | "weekly" | "monthly" | "custom";

export interface ScheduleConfig {
  frequency: ScheduleFrequency;
  minute: number;
  hour: number;
  dayOfWeek: number;
  dayOfMonth: number;
  customCron: string;
}

export const DEFAULT_SCHEDULE: ScheduleConfig = {
  frequency: "weekly",
  minute: 0,
  hour: 2,
  dayOfWeek: 1,
  dayOfMonth: 1,
  customCron: "0 2 * * 1",
};

function isFixedNumber(value: string): number | null {
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : null;
}

export function buildCronExpression(config: ScheduleConfig): string {
  const minute = Math.min(59, Math.max(0, config.minute));
  const hour = Math.min(23, Math.max(0, config.hour));
  const dayOfWeek = Math.min(6, Math.max(0, config.dayOfWeek));
  const dayOfMonth = Math.min(31, Math.max(1, config.dayOfMonth));

  switch (config.frequency) {
    case "hourly":
      return `${minute} * * * *`;
    case "daily":
      return `${minute} ${hour} * * *`;
    case "weekly":
      return `${minute} ${hour} * * ${dayOfWeek}`;
    case "monthly":
      return `${minute} ${hour} ${dayOfMonth} * *`;
    case "custom":
      return config.customCron.trim() || DEFAULT_SCHEDULE.customCron;
    default:
      return DEFAULT_SCHEDULE.customCron;
  }
}

export function parseCronExpression(expression: string | null | undefined): ScheduleConfig {
  if (!expression?.trim()) return { ...DEFAULT_SCHEDULE };

  const expr = expression.trim();
  const parts = expr.split(/\s+/);
  if (parts.length !== 5) {
    return { ...DEFAULT_SCHEDULE, frequency: "custom", customCron: expr };
  }

  const [minutePart, hourPart, domPart, monthPart, dowPart] = parts;
  if (monthPart !== "*") {
    return { ...DEFAULT_SCHEDULE, frequency: "custom", customCron: expr };
  }

  const minute = isFixedNumber(minutePart);
  if (minute === null) {
    return { ...DEFAULT_SCHEDULE, frequency: "custom", customCron: expr };
  }

  if (hourPart === "*" && domPart === "*" && dowPart === "*") {
    return { ...DEFAULT_SCHEDULE, frequency: "hourly", minute };
  }

  const hour = isFixedNumber(hourPart);
  if (hour === null || domPart !== "*") {
    if (hour !== null && domPart !== "*" && dowPart === "*") {
      const dayOfMonth = isFixedNumber(domPart);
      if (dayOfMonth !== null) {
        return {
          ...DEFAULT_SCHEDULE,
          frequency: "monthly",
          minute,
          hour,
          dayOfMonth,
          customCron: expr,
        };
      }
    }
    return { ...DEFAULT_SCHEDULE, frequency: "custom", customCron: expr };
  }

  if (dowPart === "*") {
    return { ...DEFAULT_SCHEDULE, frequency: "daily", minute, hour, customCron: expr };
  }

  const dayOfWeek = isFixedNumber(dowPart);
  if (dayOfWeek === null) {
    return { ...DEFAULT_SCHEDULE, frequency: "custom", customCron: expr };
  }

  return {
    ...DEFAULT_SCHEDULE,
    frequency: "weekly",
    minute,
    hour,
    dayOfWeek,
    customCron: expr,
  };
}

export function formatScheduleTime(hour: number, minute: number): string {
  return `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

export type ScheduleLabels = {
  hourly: (minute: string) => string;
  daily: (time: string) => string;
  weekly: (day: string, time: string) => string;
  monthly: (day: number, time: string) => string;
  custom: (expr: string) => string;
  weekdays: string[];
};

export function formatScheduleLabel(
  expression: string | null | undefined,
  labels: ScheduleLabels
): string {
  if (!expression?.trim()) return "";

  const config = parseCronExpression(expression);
  const time = formatScheduleTime(config.hour, config.minute);
  const minuteLabel = String(config.minute).padStart(2, "0");

  switch (config.frequency) {
    case "hourly":
      return labels.hourly(minuteLabel);
    case "daily":
      return labels.daily(time);
    case "weekly":
      return labels.weekly(labels.weekdays[config.dayOfWeek] ?? String(config.dayOfWeek), time);
    case "monthly":
      return labels.monthly(config.dayOfMonth, time);
    case "custom":
      return labels.custom(config.customCron || expression);
    default:
      return expression;
  }
}
