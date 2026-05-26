import { apiRequest } from "./baseClient";
import { normalizeModelInfoResponse } from "./normalizers";

export async function fetchModelInfo() {
  const response = await apiRequest("/model-info", {
    method: "GET",
  });

  return normalizeModelInfoResponse(response);
}