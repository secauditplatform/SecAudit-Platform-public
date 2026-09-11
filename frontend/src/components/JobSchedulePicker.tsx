import { useMemo } from "react";
import { useTranslation } from "../i18n/I18nProvider";
import {
  buildCronExpression,
  formatScheduleLabel,
  formatScheduleTime,
  type ScheduleConfig,
  type ScheduleFrequency,
} from "../utils/jobSchedule";

type JobSchedulePickerProps = {
  enabled: boolean;
  onEnabledChange: (enabled: boolean) => void;
  config: ScheduleConfig;
  onConfigChange: (config: ScheduleConfig) => void;
};

const FREQUENCIES: ScheduleFrequency[] = ["hourly", "daily", "weekly", "monthly", "custom"];

const FREQUENCY_LABEL_KEYS: Record<ScheduleFrequency, string> = {
  hourly: "jobs.scheduleFreqHourly",
  daily: "jobs.scheduleFreqDaily",
  weekly: "jobs.scheduleFreqWeekly",
  monthly: "jobs.scheduleFreqMonthly",
  custom: "jobs.scheduleFreqCustom",
};

export function JobSchedulePicker({
  enabled,
  onEnabledChange,
  config,
  onConfigChange,
}: JobSchedulePickerProps) {
  const { t } = useTranslation();

  const weekdayOptions = useMemo(
    () => [
      { value: 0, label: t("jobs.weekdaySun") },
      { value: 1, label: t("jobs.weekdayMon") },
      { value: 2, label: t("jobs.weekdayTue") },
      { value: 3, label: t("jobs.weekdayWed") },
      { value: 4, label: t("jobs.weekdayThu") },
      { value: 5, label: t("jobs.weekdayFri") },
      { value: 6, label: t("jobs.weekdaySat") },
    ],
    [t]
  );

  const scheduleLabels = useMemo(
    () => ({
      hourly: (minute: string) => t("jobs.scheduleLabelHourly", { minute }),
      daily: (time: string) => t("jobs.scheduleLabelDaily", { time }),
      weekly: (day: string, time: string) => t("jobs.scheduleLabelWeekly", { day, time }),
      monthly: (day: number, time: string) => t("jobs.scheduleLabelMonthly", { day, time }),
      custom: (expr: string) => t("jobs.scheduleLabelCustom", { expr }),
      weekdays: weekdayOptions.map((option) => option.label),
    }),
    [t, weekdayOptions]
  );

  const preview = formatScheduleLabel(buildCronExpression(config), scheduleLabels);
  const timeValue = formatScheduleTime(config.hour, config.minute);

  const updateConfig = (patch: Partial<ScheduleConfig>) => {
    onConfigChange({ ...config, ...patch });
  };

  const handleTimeChange = (value: string) => {
    const [hourPart, minutePart] = value.split(":");
    const hour = Number(hourPart);
    const minute = Number(minutePart);
    if (!Number.isInteger(hour) || !Number.isInteger(minute)) return;
    updateConfig({ hour, minute });
  };

  return (
    <div className="pf-schedule">
      <label className="pf-form__checkbox-label pf-schedule__toggle">
        <input
          type="checkbox"
          className="pf-checkbox-control"
          checked={enabled}
          onChange={(event) => onEnabledChange(event.target.checked)}
        />
        {t("jobs.scheduleEnabled")}
      </label>

      {enabled && (
        <div className="pf-schedule__body">
          <div className="pf-form__row pf-schedule__row">
            <div className="pf-form__group">
              <label htmlFor="job-schedule-frequency">{t("jobs.scheduleFrequency")}</label>
              <select
                id="job-schedule-frequency"
                className="pf-select"
                value={config.frequency}
                onChange={(event) => {
                  const frequency = event.target.value as ScheduleFrequency;
                  const nextConfig: ScheduleConfig = { ...config, frequency };
                  if (frequency === "custom" && !config.customCron.trim()) {
                    nextConfig.customCron = buildCronExpression(config);
                  }
                  onConfigChange(nextConfig);
                }}
              >
                {FREQUENCIES.map((frequency) => (
                  <option key={frequency} value={frequency}>
                    {t(FREQUENCY_LABEL_KEYS[frequency])}
                  </option>
                ))}
              </select>
            </div>

            {config.frequency === "hourly" && (
              <div className="pf-form__group">
                <label htmlFor="job-schedule-minute">{t("jobs.scheduleMinute")}</label>
                <select
                  id="job-schedule-minute"
                  className="pf-select"
                  value={config.minute}
                  onChange={(event) => updateConfig({ minute: Number(event.target.value) })}
                >
                  {Array.from({ length: 60 }, (_, index) => (
                    <option key={index} value={index}>
                      :{String(index).padStart(2, "0")}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {(config.frequency === "daily" ||
              config.frequency === "weekly" ||
              config.frequency === "monthly") && (
              <div className="pf-form__group">
                <label htmlFor="job-schedule-time">{t("jobs.scheduleTime")}</label>
                <input
                  id="job-schedule-time"
                  type="time"
                  className="pf-input"
                  value={timeValue}
                  onChange={(event) => handleTimeChange(event.target.value)}
                />
              </div>
            )}

            {config.frequency === "weekly" && (
              <div className="pf-form__group">
                <label htmlFor="job-schedule-weekday">{t("jobs.scheduleDayOfWeek")}</label>
                <select
                  id="job-schedule-weekday"
                  className="pf-select"
                  value={config.dayOfWeek}
                  onChange={(event) => updateConfig({ dayOfWeek: Number(event.target.value) })}
                >
                  {weekdayOptions.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {config.frequency === "monthly" && (
              <div className="pf-form__group">
                <label htmlFor="job-schedule-dom">{t("jobs.scheduleDayOfMonth")}</label>
                <select
                  id="job-schedule-dom"
                  className="pf-select"
                  value={config.dayOfMonth}
                  onChange={(event) => updateConfig({ dayOfMonth: Number(event.target.value) })}
                >
                  {Array.from({ length: 31 }, (_, index) => {
                    const day = index + 1;
                    return (
                      <option key={day} value={day}>
                        {t("jobs.scheduleDayOfMonthOption", { day })}
                      </option>
                    );
                  })}
                </select>
              </div>
            )}
          </div>

          {config.frequency === "custom" && (
            <div className="pf-form__group">
              <label htmlFor="job-schedule-cron">{t("jobs.scheduleCustomCron")}</label>
              <input
                id="job-schedule-cron"
                className="pf-input pf-input--mono"
                value={config.customCron}
                onChange={(event) => updateConfig({ customCron: event.target.value })}
                placeholder="0 2 * * 1"
              />
              <p className="pf-form__hint">{t("jobs.scheduleCustomHint")}</p>
            </div>
          )}

          <p className="pf-schedule__preview">
            {t("jobs.schedulePreview", { label: preview })}
          </p>
        </div>
      )}
    </div>
  );
}

export function useScheduleLabels() {
  const { t } = useTranslation();

  return useMemo(
    () => ({
      hourly: (minute: string) => t("jobs.scheduleLabelHourly", { minute }),
      daily: (time: string) => t("jobs.scheduleLabelDaily", { time }),
      weekly: (day: string, time: string) => t("jobs.scheduleLabelWeekly", { day, time }),
      monthly: (day: number, time: string) => t("jobs.scheduleLabelMonthly", { day, time }),
      custom: (expr: string) => t("jobs.scheduleLabelCustom", { expr }),
      weekdays: [
        t("jobs.weekdaySun"),
        t("jobs.weekdayMon"),
        t("jobs.weekdayTue"),
        t("jobs.weekdayWed"),
        t("jobs.weekdayThu"),
        t("jobs.weekdayFri"),
        t("jobs.weekdaySat"),
      ],
    }),
    [t]
  );
}
