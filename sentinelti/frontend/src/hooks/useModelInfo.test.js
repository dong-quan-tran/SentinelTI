import { renderHook, waitFor, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import useModelInfo from "./useModelInfo";
import { fetchModelInfo } from "../api/modelApi";

vi.mock("../api/modelApi", () => ({
  fetchModelInfo: vi.fn(),
}));

const mockModelInfo = {
  schema_version: "1.1",
  model_meta: {
    model_type: "xgb",
    threshold: 0.75,
    threshold_source: "metadata",
    recommended_threshold: 0.8,
    recommended_threshold_source: "artifact",
    metrics: {
      roc_auc: 0.99,
      average_precision: 0.98,
    },
    class_labels: {
      benign: 0,
      malicious: 1,
    },
    class_counts: {
      train_0: 10,
      train_1: 5,
      test_0: 4,
      test_1: 2,
    },
    dataset_source: {},
    training_params: {},
    training_notes: [],
    top_features: [],
    model_summary: {
      model_type: "xgb",
      dataset_name: null,
      trained_at: null,
      top_features: [],
    },
  },
};

describe("useModelInfo", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("loads model info on mount", async () => {
    fetchModelInfo.mockResolvedValue(mockModelInfo);

    const { result } = renderHook(() => useModelInfo());

    expect(result.current.loadingModel).toBe(true);
    expect(result.current.modelInfo).toBe(null);
    expect(result.current.modelInfoError).toBe("");

    await waitFor(() => {
      expect(result.current.loadingModel).toBe(false);
    });

    expect(fetchModelInfo).toHaveBeenCalledTimes(1);
    expect(result.current.modelInfo).toEqual(mockModelInfo);
    expect(result.current.modelInfoError).toBe("");
  });

  it("stores an error and clears model info when the request fails", async () => {
    fetchModelInfo.mockRejectedValue(new Error("Model info failed to load"));

    const { result } = renderHook(() => useModelInfo());

    await waitFor(() => {
      expect(result.current.loadingModel).toBe(false);
    });

    expect(fetchModelInfo).toHaveBeenCalledTimes(1);
    expect(result.current.modelInfo).toBe(null);
    expect(result.current.modelInfoError).toBe("Model info failed to load");
  });

  it("falls back to a default error message when the error has no message", async () => {
    fetchModelInfo.mockRejectedValue({});

    const { result } = renderHook(() => useModelInfo());

    await waitFor(() => {
      expect(result.current.loadingModel).toBe(false);
    });

    expect(result.current.modelInfo).toBe(null);
    expect(result.current.modelInfoError).toBe(
      "Could not load model information right now."
    );
  });

  it("reloadModelInfo refreshes the model info successfully", async () => {
    fetchModelInfo
      .mockResolvedValueOnce(mockModelInfo)
      .mockResolvedValueOnce({
        ...mockModelInfo,
        model_meta: {
          ...mockModelInfo.model_meta,
          threshold: 0.8,
        },
      });

    const { result } = renderHook(() => useModelInfo());

    await waitFor(() => {
      expect(result.current.loadingModel).toBe(false);
    });

    await act(async () => {
      const response = await result.current.reloadModelInfo();
      expect(response).toEqual({
        ok: true,
        data: {
          ...mockModelInfo,
          model_meta: {
            ...mockModelInfo.model_meta,
            threshold: 0.8,
          },
        },
      });
    });

    expect(fetchModelInfo).toHaveBeenCalledTimes(2);
    expect(result.current.modelInfo.model_meta.threshold).toBe(0.8);
    expect(result.current.modelInfoError).toBe("");
  });

  it("reloadModelInfo returns an error result when refresh fails", async () => {
    fetchModelInfo
      .mockResolvedValueOnce(mockModelInfo)
      .mockRejectedValueOnce(new Error("Reload failed"));

    const { result } = renderHook(() => useModelInfo());

    await waitFor(() => {
      expect(result.current.loadingModel).toBe(false);
    });

    await act(async () => {
      const response = await result.current.reloadModelInfo();
      expect(response).toEqual({
        ok: false,
        error: "Reload failed",
      });
    });

    expect(fetchModelInfo).toHaveBeenCalledTimes(2);
    expect(result.current.modelInfo).toBe(null);
    expect(result.current.modelInfoError).toBe("Reload failed");
    expect(result.current.loadingModel).toBe(false);
  });
});