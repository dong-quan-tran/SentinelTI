import { useCallback, useEffect, useState } from "react";
import { fetchModelInfo } from "../api/client";

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
      const message = `Could not load model info: ${error.message}`;
      setModelInfoError(message);
      setModelInfo(null);
      return { ok: false, error: message };
    } finally {
      setLoadingModel(false);
    }
  }, []);

  useEffect(() => {
    loadModelInfo();
  }, [loadModelInfo]);

  return {
    modelInfo,
    loadingModel,
    modelInfoError,
    reloadModelInfo: loadModelInfo,
  };
}