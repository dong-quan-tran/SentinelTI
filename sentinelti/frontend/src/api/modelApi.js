import { apiRequest } from "./baseClient";

export function fetchModelInfo() {
  return apiRequest("/model-info", {
    method: "GET",
  });
}