import { useEffect } from "react";
import { useLocation } from "react-router-dom";

export function scrollAppToTop(): void {
  const main = document.querySelector<HTMLElement>(".pf-main");
  if (!main) return;
  main.scrollTop = 0;
  main.scrollLeft = 0;
}

export function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    scrollAppToTop();
    requestAnimationFrame(() => {
      scrollAppToTop();
    });
  }, [pathname]);

  return null;
}
