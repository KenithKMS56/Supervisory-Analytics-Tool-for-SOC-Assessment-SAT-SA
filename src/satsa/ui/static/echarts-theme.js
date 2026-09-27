/* SAT-SA ECharts theme — Light & Dark Modes
 * Palette: Electric Iris (#8052ff), Saffron Spark (#ffb829 / #b45309), Deep Verdant (#15846e / #0f766e),
 * Critical Red (#ff4d4f / #dc2626), Sky Accent (#38bdf8), Silver Mist (#bdbdbd)
 * Typography: Inter
 */
(function () {
  if (typeof echarts === "undefined" || typeof echarts.registerTheme !== "function") {
    return;
  }

  var FONT_FAMILY = 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';

  // 1. Dark Theme
  var darkTheme = {
    color: ["#B7D334", "#ffb829", "#15846e", "#ff4d4f", "#38bdf8", "#bdbdbd"],
    backgroundColor: "transparent",
    textStyle: { fontFamily: FONT_FAMILY, color: "#ffffff", fontWeight: 200 },
    title: { textStyle: { fontFamily: FONT_FAMILY, color: "#ffffff", fontWeight: 400 } },
    legend: {
      textStyle: { fontFamily: FONT_FAMILY, color: "#9a9a9a", fontSize: 12, fontWeight: 400 }
    },
    tooltip: {
      backgroundColor: "rgba(12, 12, 14, 0.95)",
      borderColor: "rgba(255, 255, 255, 0.15)",
      borderWidth: 1,
      textStyle: { fontFamily: FONT_FAMILY, color: "#ffffff", fontSize: 12 },
      extraCssText: "border-radius:12px;box-shadow:none;border:1px solid rgba(255,255,255,0.15);padding:8px 12px;"
    },
    categoryAxis: {
      axisLine: { lineStyle: { color: "rgba(255, 255, 255, 0.12)" } },
      axisTick: { lineStyle: { color: "rgba(255, 255, 255, 0.12)" } },
      axisLabel: { color: "#9a9a9a", fontFamily: FONT_FAMILY, fontSize: 11 },
      splitLine: { show: false }
    },
    valueAxis: {
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: "#9a9a9a", fontFamily: FONT_FAMILY, fontSize: 11 },
      splitLine: { lineStyle: { color: "rgba(255, 255, 255, 0.06)" } }
    },
    radar: {
      name: { textStyle: { color: "#9a9a9a", fontFamily: FONT_FAMILY, fontSize: 12 } },
      axisLine: { lineStyle: { color: "rgba(255, 255, 255, 0.12)" } },
      splitLine: { lineStyle: { color: "rgba(255, 255, 255, 0.06)" } },
      splitArea: { areaStyle: { color: ["transparent", "rgba(255, 255, 255, 0.02)"] } }
    },
    visualMap: {
      textStyle: { color: "#9a9a9a", fontFamily: FONT_FAMILY }
    }
  };

  // 2. Light Theme (Default)
  var lightTheme = {
    color: ["#8FA723", "#b45309", "#0f766e", "#dc2626", "#0284c7", "#64748b"],
    backgroundColor: "transparent",
    textStyle: { fontFamily: FONT_FAMILY, color: "#0f172a", fontWeight: 200 },
    title: { textStyle: { fontFamily: FONT_FAMILY, color: "#0f172a", fontWeight: 400 } },
    legend: {
      textStyle: { fontFamily: FONT_FAMILY, color: "#64748b", fontSize: 12, fontWeight: 400 }
    },
    tooltip: {
      backgroundColor: "rgba(255, 255, 255, 0.98)",
      borderColor: "#e2e8f0",
      borderWidth: 1,
      textStyle: { fontFamily: FONT_FAMILY, color: "#0f172a", fontSize: 12 },
      extraCssText: "border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,0.08);border:1px solid #e2e8f0;padding:8px 12px;"
    },
    categoryAxis: {
      axisLine: { lineStyle: { color: "#e2e8f0" } },
      axisTick: { lineStyle: { color: "#e2e8f0" } },
      axisLabel: { color: "#64748b", fontFamily: FONT_FAMILY, fontSize: 11 },
      splitLine: { show: false }
    },
    valueAxis: {
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: "#64748b", fontFamily: FONT_FAMILY, fontSize: 11 },
      splitLine: { lineStyle: { color: "#f1f5f9" } }
    },
    radar: {
      name: { textStyle: { color: "#64748b", fontFamily: FONT_FAMILY, fontSize: 12 } },
      axisLine: { lineStyle: { color: "#e2e8f0" } },
      splitLine: { lineStyle: { color: "#f1f5f9" } },
      splitArea: { areaStyle: { color: ["transparent", "rgba(0, 0, 0, 0.015)"] } }
    },
    visualMap: {
      textStyle: { color: "#64748b", fontFamily: FONT_FAMILY }
    }
  };

  echarts.registerTheme("satsa-dark", darkTheme);
  echarts.registerTheme("satsa-light", lightTheme);
  echarts.registerTheme("satsa", lightTheme);

  window.satsaGetChartTheme = function () {
    var theme = document.documentElement.getAttribute("data-theme") || "light";
    return theme === "dark" ? "satsa-dark" : "satsa-light";
  };
})();
