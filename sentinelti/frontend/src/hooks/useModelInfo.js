import { useCallback, useEffect, useState } from "react";
import { fetchModelInfo } from "../api/modelApi";

export default function useModelInfo() {
  const [modelInfo, setModelInfo] = useState(null);
  const [loadingModel, setLoadingModel] = useState(true);
  const [modelInfoError, setModelInfoError] = useState("");

  const loadModelInfo = useCallback(async () => {
    try {
      setLoadingModel(true);
      setModelInfoError("");
      const data = await fetchModelInfo();
      setModelInfo(data);
      return { ok: true, data };
    } catch (error) {
      const message =
        error?.message || "Could not load model information right now.";
      setModelInfoError(message);
      setModelInfo(null);
      return { ok: false, error: message };
    } finally {
      setLoadingModel(false);
    }
  }, []);

  useEffect(() => {
    let active = true;

    fetchModelInfo()
      .then((data) => {
        if (active) {
          setModelInfo(data);
          setLoadingModel(false);
        }
      })
      .catch((error) => {
        if (active) {
          setModelInfoError(
            error?.message || "Could not load model information right now."
          );
          setModelInfo(null);
          setLoadingModel(false);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  return {
    modelInfo,
    loadingModel,
    modelInfoError,
    reloadModelInfo: loadModelInfo,
  };
}