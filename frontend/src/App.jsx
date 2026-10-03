import { useCallback, useEffect, useMemo, useRef, useState } from "react";

const API_BASE_URL = "http://127.0.0.1:8000";

const initialForm = {
  sender: "",
  subject: "",
  body: "",
  urls: "",
  attachment_name: "",
};

function firstDefined(...values) {
  return values.find(
    (value) => value !== undefined && value !== null && value !== "",
  );
}

function normalizeClassification(classification, score) {
  const value = String(classification || "").toUpperCase();

  if (
    value.includes("HIGH") ||
    value.includes("PHISHING") ||
    value.includes("LIKELY")
  ) {
    return "HIGH RISK";
  }

  if (value.includes("SUSPICIOUS")) {
    return "SUSPICIOUS";
  }

  if (value.includes("MODERATE")) {
    return "MODERATE RISK";
  }

  if (value.includes("LOW") || value.includes("SAFE")) {
    return "LOW RISK";
  }

  const numericScore = Number(score || 0);

  if (numericScore >= 71) {
    return "HIGH RISK";
  }

  if (numericScore >= 41) {
    return "SUSPICIOUS";
  }

  if (numericScore >= 21) {
    return "MODERATE RISK";
  }

  return "LOW RISK";
}

function extractUrls(text) {
  const matches = String(text || "").match(
    /\bhttps?:\/\/[^\s<>"']+/gi,
  );

  if (!matches) {
    return [];
  }

  return [
    ...new Set(
      matches.map((url) =>
        url.replace(/[),.;!?]+$/g, ""),
      ),
    ),
  ];
}

function extractHeader(text, headerName) {
  const pattern = new RegExp(
    `^${headerName}:\\s*(.+)$`,
    "im",
  );

  const match = String(text || "").match(pattern);

  return match ? match[1].trim() : "";
}

function extractAttachmentName(text) {
  const source = String(text || "");

  const filenameMatches = [
    /filename\s*=\s*"?([^";\r\n]+)"?/i,
    /name\s*=\s*"?([^";\r\n]+)"?/i,
    /attachment\s*:\s*([^\s\r\n]+)/i,
  ];

  for (const pattern of filenameMatches) {
    const match = source.match(pattern);

    if (match?.[1]) {
      return match[1].trim();
    }
  }

  return "";
}

function parseUploadedEmail(text) {
  const source = String(text || "").replace(/\r\n/g, "\n");

  const separatorIndex = source.indexOf("\n\n");

  const headerText =
    separatorIndex >= 0
      ? source.slice(0, separatorIndex)
      : source;

  let body =
    separatorIndex >= 0
      ? source.slice(separatorIndex + 2).trim()
      : source.trim();

  const sender =
    extractHeader(source, "From") ||
    extractHeader(source, "Sender");

  const subject = extractHeader(source, "Subject");

  const urls = extractUrls(source);

  const attachmentName = extractAttachmentName(source);

  /*
   * Do not render raw HTML email content.
   * This keeps the upload workflow text-only and avoids
   * treating uploaded HTML as trusted browser content.
   */
  body = body
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]*>/g, " ")
    .replace(/[ \t]{2,}/g, " ")
    .replace(/\n{3,}/g, "\n")
    .trim();

  return {
    sender,
    subject,
    body,
    urls,
    attachmentName,
    headerText,
  };
}

function App() {
  const [activeSection, setActiveSection] =
    useState("dashboard");

  const [backendStatus, setBackendStatus] =
    useState("Not checked");

  const [checkingBackend, setCheckingBackend] =
    useState(false);

  const [form, setForm] = useState(initialForm);

  const [analyzing, setAnalyzing] =
    useState(false);

  const [result, setResult] = useState(null);

  const [error, setError] = useState("");

  const [dashboardStats, setDashboardStats] =
    useState(null);

  const [dashboardIndicators, setDashboardIndicators] =
    useState([]);

  const [history, setHistory] = useState([]);

  const [loadingDashboard, setLoadingDashboard] =
    useState(false);

  const [loadingHistory, setLoadingHistory] =
    useState(false);

  const [deletingId, setDeletingId] =
    useState(null);

  const [urlInput, setUrlInput] =
    useState("");

  const [urlAnalyzing, setUrlAnalyzing] =
    useState(false);

  const [urlResult, setUrlResult] =
    useState(null);

  const [urlError, setUrlError] =
    useState("");

  const [awarenessOpen, setAwarenessOpen] =
    useState(null);

  const [fileLoading, setFileLoading] =
    useState(false);

  const [fileStatus, setFileStatus] =
    useState("");

  const fileInputRef = useRef(null);

  const updateField = (field, value) => {
    setForm((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const scrollToSection = (sectionId) => {
    const element =
      document.getElementById(sectionId);

    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }

    setActiveSection(sectionId);
  };

  const checkBackend = async () => {
    setCheckingBackend(true);
    setBackendStatus("Checking...");

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/health`,
      );

      if (!response.ok) {
        throw new Error(
          `Backend returned HTTP ${response.status}`,
        );
      }

      const data = await response.json();

      setBackendStatus(
        data?.status
          ? `Connected: ${String(
              data.status,
            ).toUpperCase()}`
          : "Connected",
      );
    } catch (backendError) {
      setBackendStatus(
        `Connection failed: ${backendError.message}`,
      );
    } finally {
      setCheckingBackend(false);
    }
  };

  const loadDashboardData =
    useCallback(async () => {
      setLoadingDashboard(true);

      try {
        const [
          statsResponse,
          indicatorsResponse,
        ] = await Promise.all([
          fetch(
            `${API_BASE_URL}/api/dashboard/stats`,
          ),
          fetch(
            `${API_BASE_URL}/api/dashboard/indicators`,
          ),
        ]);

        const statsData =
          await statsResponse.json();

        const indicatorsData =
          await indicatorsResponse.json();

        if (!statsResponse.ok) {
          throw new Error(
            statsData?.detail ||
              `Dashboard stats failed with HTTP ${statsResponse.status}`,
          );
        }

        if (!indicatorsResponse.ok) {
          throw new Error(
            indicatorsData?.detail ||
              `Dashboard indicators failed with HTTP ${indicatorsResponse.status}`,
          );
        }

        setDashboardStats(statsData);

        if (Array.isArray(indicatorsData)) {
          setDashboardIndicators(
            indicatorsData,
          );
        } else if (
          Array.isArray(
            indicatorsData?.indicators,
          )
        ) {
          setDashboardIndicators(
            indicatorsData.indicators,
          );
        } else if (
          Array.isArray(indicatorsData?.data)
        ) {
          setDashboardIndicators(
            indicatorsData.data,
          );
        } else {
          setDashboardIndicators([]);
        }
      } catch (dashboardError) {
        console.error(
          "Dashboard loading error:",
          dashboardError,
        );
      } finally {
        setLoadingDashboard(false);
      }
    }, []);

  const loadHistory =
    useCallback(async () => {
      setLoadingHistory(true);

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/analyses`,
        );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data?.detail ||
              `History request failed with HTTP ${response.status}`,
          );
        }

        if (Array.isArray(data)) {
          setHistory(data);
        } else if (
          Array.isArray(data?.analyses)
        ) {
          setHistory(data.analyses);
        } else if (
          Array.isArray(data?.data)
        ) {
          setHistory(data.data);
        } else if (
          Array.isArray(data?.items)
        ) {
          setHistory(data.items);
        } else {
          setHistory([]);
        }
      } catch (historyError) {
        console.error(
          "History loading error:",
          historyError,
        );

        setHistory([]);
      } finally {
        setLoadingHistory(false);
      }
    }, []);

  const refreshDashboard =
    useCallback(async () => {
      await Promise.all([
        loadDashboardData(),
        loadHistory(),
      ]);
    }, [
      loadDashboardData,
      loadHistory,
    ]);

  useEffect(() => {
    checkBackend();
    refreshDashboard();
  }, [refreshDashboard]);

  useEffect(() => {
    const sections = [
      "dashboard",
      "email-analyzer",
      "url-analyzer",
      "awareness",
      "history",
    ];

    const handleScroll = () => {
      const scrollPosition =
        window.scrollY + 180;

      let currentSection =
        "dashboard";

      sections.forEach(
        (sectionId) => {
          const section =
            document.getElementById(
              sectionId,
            );

          if (
            section &&
            section.offsetTop <=
              scrollPosition
          ) {
            currentSection =
              sectionId;
          }
        },
      );

      setActiveSection(
        currentSection,
      );
    };

    window.addEventListener(
      "scroll",
      handleScroll,
    );

    return () => {
      window.removeEventListener(
        "scroll",
        handleScroll,
      );
    };
  }, []);

  const handleAnalyze = async (
    event,
  ) => {
    event.preventDefault();

    setError("");
    setResult(null);

    if (!form.sender.trim()) {
      setError(
        "Please enter the sender email address.",
      );
      return;
    }

    if (!form.subject.trim()) {
      setError(
        "Please enter the email subject.",
      );
      return;
    }

    if (!form.body.trim()) {
      setError(
        "Please enter the email body.",
      );
      return;
    }

    const urls = form.urls
      .split(/\r?\n/)
      .map((url) => url.trim())
      .filter(Boolean);

    const payload = {
      sender: form.sender.trim(),
      subject: form.subject.trim(),
      body: form.body.trim(),
      urls,
      attachment_name:
        form.attachment_name.trim(),
    };

    setAnalyzing(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/analyze`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify(
            payload,
          ),
        },
      );

      const data =
        await response.json();

      if (!response.ok) {
        const detail =
          data?.detail ||
          data?.message ||
          `Analysis failed with HTTP ${response.status}`;

        if (Array.isArray(detail)) {
          throw new Error(
            detail
              .map(
                (item) =>
                  item?.msg ||
                  "Invalid input",
              )
              .join(", "),
          );
        }

        throw new Error(
          String(detail),
        );
      }

      setResult(data);

      await refreshDashboard();
    } catch (analysisError) {
      setError(
        analysisError.message ||
          "Unable to analyze the email.",
      );
    } finally {
      setAnalyzing(false);
    }
  };

  const handleFileUpload = async (
    event,
  ) => {
    const file =
      event.target.files?.[0];

    if (!file) {
      return;
    }

    setFileLoading(true);
    setFileStatus("");
    setError("");

    const lowerName =
      file.name.toLowerCase();

    const isAllowed =
      lowerName.endsWith(".txt") ||
      lowerName.endsWith(".eml");

    if (!isAllowed) {
      setFileStatus(
        "Unsupported file. Please select a .txt or .eml file.",
      );
      setFileLoading(false);

      if (fileInputRef.current) {
        fileInputRef.current.value =
          "";
      }

      return;
    }

    const maximumSize =
      1024 * 1024;

    if (file.size > maximumSize) {
      setFileStatus(
        "File is too large. Please use a file smaller than 1 MB.",
      );
      setFileLoading(false);

      if (fileInputRef.current) {
        fileInputRef.current.value =
          "";
      }

      return;
    }

    try {
      const text =
        await file.text();

      const parsed =
        parseUploadedEmail(text);

      const extractedUrls =
        parsed.urls;

      setForm({
        sender: parsed.sender,
        subject: parsed.subject,
        body: parsed.body,
        urls:
          extractedUrls.join("\n"),
        attachment_name:
          parsed.attachmentName,
      });

      setResult(null);

      const extractedParts = [];

      if (parsed.sender) {
        extractedParts.push(
          "sender",
        );
      }

      if (parsed.subject) {
        extractedParts.push(
          "subject",
        );
      }

      if (parsed.body) {
        extractedParts.push(
          "body",
        );
      }

      if (parsed.urls.length > 0) {
        extractedParts.push(
          `${parsed.urls.length} URL${
            parsed.urls.length === 1
              ? ""
              : "s"
          }`,
        );
      }

      if (
        parsed.attachmentName
      ) {
        extractedParts.push(
          "attachment name",
        );
      }

      if (
        extractedParts.length > 0
      ) {
        setFileStatus(
          `${file.name} loaded. Extracted: ${extractedParts.join(
            ", ",
          )}. Review the fields before analysis.`,
        );
      } else {
        setFileStatus(
          `${file.name} was loaded, but no standard From/Subject/body fields were detected.`,
        );
      }
    } catch (fileError) {
      setFileStatus(
        `Unable to read the file: ${fileError.message}`,
      );
    } finally {
      setFileLoading(false);

      if (fileInputRef.current) {
        fileInputRef.current.value =
          "";
      }
    }
  };

  const analyzeUrl = async (
    event,
  ) => {
    event.preventDefault();

    setUrlError("");
    setUrlResult(null);

    const cleanUrl =
      urlInput.trim();

    if (!cleanUrl) {
      setUrlError(
        "Please enter a URL.",
      );
      return;
    }

    setUrlAnalyzing(true);

    try {
      const response =
        await fetch(
          `${API_BASE_URL}/api/analyze/url`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json",
            },
            body: JSON.stringify({
              url: cleanUrl,
            }),
          },
        );

      const data =
        await response.json();

      if (!response.ok) {
        const detail =
          data?.detail ||
          data?.message ||
          `URL analysis failed with HTTP ${response.status}`;

        if (Array.isArray(detail)) {
          throw new Error(
            detail
              .map(
                (item) =>
                  item?.msg ||
                  "Invalid URL input",
              )
              .join(", "),
          );
        }

        throw new Error(
          String(detail),
        );
      }

      setUrlResult(data);
    } catch (urlAnalysisError) {
      setUrlError(
        urlAnalysisError.message ||
          "Unable to analyze the URL.",
      );
    } finally {
      setUrlAnalyzing(false);
    }
  };

  const deleteAnalysis =
    async (analysisId) => {
      if (
        analysisId ===
          undefined ||
        analysisId === null
      ) {
        return;
      }

      setDeletingId(analysisId);

      try {
        const response =
          await fetch(
            `${API_BASE_URL}/api/analyses/${analysisId}`,
            {
              method: "DELETE",
            },
          );

        const data =
          await response.json();

        if (!response.ok) {
          throw new Error(
            data?.detail ||
              `Delete failed with HTTP ${response.status}`,
          );
        }

        setHistory((current) =>
          current.filter(
            (item) => {
              const id =
                firstDefined(
                  item?.id,
                  item?.analysis_id,
                );

              return (
                String(id) !==
                String(analysisId)
              );
            },
          ),
        );

        await loadDashboardData();
      } catch (deleteError) {
        setError(
          deleteError.message ||
            "Unable to delete analysis.",
        );
      } finally {
        setDeletingId(null);
      }
    };

  const clearAnalyzer = () => {
    setForm(initialForm);
    setResult(null);
    setError("");
    setFileStatus("");
  };

  const clearUrlAnalyzer = () => {
    setUrlInput("");
    setUrlResult(null);
    setUrlError("");
  };

  const resultData = useMemo(() => {
    if (!result) {
      return null;
    }

    const nested =
      result?.explainability ||
      result?.explanation ||
      {};

    const score = Number(
      firstDefined(
        result?.hybrid_score,
        result?.risk_score,
        result?.score,
        nested?.hybrid_score,
        nested?.risk_score,
        result?.rule_score,
        0,
      ),
    );

    const classification =
      firstDefined(
        result?.classification,
        nested?.classification,
        "CLASSIFICATION NOT AVAILABLE",
      );

    const why =
      firstDefined(
        result?.why,
        result?.summary,
        nested?.why,
        nested?.summary,
        result?.explanation_text,
        "",
      );

    const rawFindingGroups = [
      result?.findings,
      nested?.findings,
      result?.sender_findings,
      result?.content_findings,
      result?.url_findings,
      result?.attachment_findings,
    ];

    const findings = [];

    rawFindingGroups.forEach(
      (group) => {
        if (!Array.isArray(group)) {
          return;
        }

        group.forEach((item) => {
          if (typeof item === "string") {
            findings.push(item);
            return;
          }

          if (
            item &&
            typeof item ===
              "object"
          ) {
            const textValue =
              item.message ||
              item.finding ||
              item.description ||
              item.reason ||
              item.text;

            if (textValue) {
              findings.push(
                String(textValue),
              );
            }
          }
        });
      },
    );

    const recommendations =
      result?.recommendations ||
      nested?.recommendations ||
      [];

    return {
      score: Math.max(
        0,
        Math.min(100, score),
      ),
      classification:
        String(classification),
      why: String(why),
      findings: [
        ...new Set(findings),
      ],
      recommendations:
        Array.isArray(
          recommendations,
        )
          ? recommendations.map(
              (item) => {
                if (
                  typeof item ===
                  "string"
                ) {
                  return item;
                }

                return (
                  item?.message ||
                  item?.recommendation ||
                  item?.text ||
                  item?.description ||
                  JSON.stringify(item)
                );
              },
            )
          : [],
    };
  }, [result]);

  const urlResultData = useMemo(() => {
    if (!urlResult) {
      return null;
    }

    const nested =
      urlResult?.analysis ||
      urlResult?.result ||
      urlResult?.data ||
      {};

    const score = Number(
      firstDefined(
        urlResult?.risk_score,
        urlResult?.score,
        urlResult?.url_risk_score,
        nested?.risk_score,
        nested?.score,
        0,
      ),
    );

    const classification =
      String(
        firstDefined(
          urlResult?.classification,
          urlResult?.risk_level,
          nested?.classification,
          nested?.risk_level,
          "URL ANALYSIS COMPLETED",
        ),
      );

    const suspicious =
      Boolean(
        firstDefined(
          urlResult?.is_suspicious,
          urlResult?.suspicious,
          nested?.is_suspicious,
          false,
        ),
      );

    const findings = [];

    const findingGroups = [
      urlResult?.findings,
      urlResult?.url_findings,
      nested?.findings,
      nested?.url_findings,
    ];

    findingGroups.forEach(
      (group) => {
        if (!Array.isArray(group)) {
          return;
        }

        group.forEach((item) => {
          if (typeof item === "string") {
            findings.push(item);
            return;
          }

          if (
            item &&
            typeof item ===
              "object"
          ) {
            const textValue =
              item.message ||
              item.finding ||
              item.description ||
              item.reason ||
              item.text;

            if (textValue) {
              findings.push(
                String(textValue),
              );
            }
          }
        });
      },
    );

    const indicators = {
      scheme: firstDefined(
        urlResult?.scheme,
        nested?.scheme,
        "—",
      ),

      hostname: firstDefined(
        urlResult?.hostname,
        nested?.hostname,
        "—",
      ),

      path: firstDefined(
        urlResult?.path,
        nested?.path,
        "—",
      ),

      urlLength: firstDefined(
        urlResult?.url_length,
        nested?.url_length,
        "—",
      ),

      hostnameLength:
        firstDefined(
          urlResult?.hostname_length,
          nested?.hostname_length,
          "—",
        ),

      subdomainCount:
        firstDefined(
          urlResult?.subdomain_count,
          nested?.subdomain_count,
          "—",
        ),

      hasIpUrl: firstDefined(
        urlResult?.has_ip_url,
        nested?.has_ip_url,
        false,
      ),

      hasShortenedUrlPattern:
        firstDefined(
          urlResult?.has_shortened_url_pattern,
          nested?.has_shortened_url_pattern,
          false,
        ),

      hasSuspiciousKeywords:
        firstDefined(
          urlResult?.has_suspicious_keywords,
          nested?.has_suspicious_keywords,
          false,
        ),

      https: firstDefined(
        urlResult?.is_https,
        nested?.is_https,
        String(
          firstDefined(
            urlResult?.scheme,
            nested?.scheme,
            "",
          ),
        ).toLowerCase() ===
          "https",
      ),
    };

    return {
      score: Math.max(
        0,
        Math.min(100, score),
      ),
      classification,
      suspicious,
      findings: [
        ...new Set(findings),
      ],
      indicators,
    };
  }, [urlResult]);

  const classificationClass =
    useMemo(() => {
      if (!resultData) {
        return "neutral";
      }

      const value =
        resultData.classification.toUpperCase();

      if (
        value.includes("HIGH") ||
        value.includes("PHISHING")
      ) {
        return "danger";
      }

      if (
        value.includes("SUSPICIOUS")
      ) {
        return "warning";
      }

      if (
        value.includes("MODERATE")
      ) {
        return "moderate";
      }

      if (
        value.includes("LOW") ||
        value.includes("SAFE")
      ) {
        return "safe";
      }

      return "neutral";
    }, [resultData]);

  const urlClassificationClass =
    useMemo(() => {
      if (!urlResultData) {
        return "neutral";
      }

      const value =
        urlResultData.classification.toUpperCase();

      if (
        urlResultData.suspicious ||
        value.includes("HIGH") ||
        value.includes("SUSPICIOUS") ||
        value.includes("PHISH")
      ) {
        return "danger";
      }

      if (
        value.includes("MODERATE")
      ) {
        return "moderate";
      }

      if (
        value.includes("LOW") ||
        value.includes("SAFE")
      ) {
        return "safe";
      }

      return "neutral";
    }, [urlResultData]);

  const statsData = useMemo(() => {
    const stats =
      dashboardStats || {};

    return {
      total: Number(
        firstDefined(
          stats.total_emails,
          stats.total_analyses,
          stats.total,
          stats.count,
          stats?.stats?.total_emails,
          0,
        ),
      ),

      phishing: Number(
        firstDefined(
          stats.likely_phishing,
          stats.phishing_count,
          stats.phishing,
          stats.high_risk,
          stats?.stats?.likely_phishing,
          0,
        ),
      ),

      suspicious: Number(
        firstDefined(
          stats.suspicious,
          stats.suspicious_count,
          stats.suspicious_emails,
          stats?.stats?.suspicious,
          0,
        ),
      ),

      lowRisk: Number(
        firstDefined(
          stats.low_risk,
          stats.low_risk_count,
          stats.safe_count,
          stats?.stats?.low_risk,
          0,
        ),
      ),

      averageRisk: Number(
        firstDefined(
          stats.average_risk,
          stats.avg_risk,
          stats.mean_risk,
          stats?.stats?.average_risk,
          0,
        ),
      ),
    };
  }, [dashboardStats]);

  const normalizedIndicators =
    useMemo(() => {
      return dashboardIndicators
        .map((item) => {
          if (
            typeof item ===
            "string"
          ) {
            return {
              name: item,
              count: 0,
            };
          }

          return {
            name: String(
              firstDefined(
                item?.indicator,
                item?.name,
                item?.type,
                item?.label,
                "Unknown Indicator",
              ),
            ),

            count: Number(
              firstDefined(
                item?.count,
                item?.total,
                item?.occurrences,
                item?.value,
                0,
              ),
            ),
          };
        })
        .sort(
          (a, b) =>
            b.count - a.count,
        )
        .slice(0, 6);
    }, [dashboardIndicators]);

  const maxIndicatorCount =
    Math.max(
      1,
      ...normalizedIndicators.map(
        (item) => item.count,
      ),
    );

  const historyMetrics =
    useMemo(() => {
      const classificationCounts =
        {
          "LOW RISK": 0,
          "MODERATE RISK": 0,
          SUSPICIOUS: 0,
          "HIGH RISK": 0,
        };

      const riskBuckets = {
        "0–20": 0,
        "21–40": 0,
        "41–70": 0,
        "71–100": 0,
      };

      const dailyMap =
        new Map();

      history.forEach((item) => {
        const score =
          Math.max(
            0,
            Math.min(
              100,
              Number(
                firstDefined(
                  item?.hybrid_score,
                  item?.risk_score,
                  item?.score,
                  item?.rule_score,
                  0,
                ),
              ),
            ),
          );

        const classification =
          normalizeClassification(
            firstDefined(
              item?.classification,
              item?.risk_level,
              "",
            ),
            score,
          );

        classificationCounts[
          classification
        ] =
          (classificationCounts[
            classification
          ] || 0) + 1;

        if (score <= 20) {
          riskBuckets["0–20"] +=
            1;
        } else if (score <= 40) {
          riskBuckets["21–40"] +=
            1;
        } else if (score <= 70) {
          riskBuckets["41–70"] +=
            1;
        } else {
          riskBuckets["71–100"] +=
            1;
        }

        const createdAt =
          firstDefined(
            item?.created_at,
            item?.timestamp,
            item?.analyzed_at,
            "",
          );

        if (createdAt) {
          const date =
            new Date(createdAt);

          if (
            !Number.isNaN(
              date.getTime(),
            )
          ) {
            const key =
              date
                .toISOString()
                .slice(0, 10);

            if (
              !dailyMap.has(key)
            ) {
              dailyMap.set(key, {
                date: key,
                total: 0,
                riskTotal: 0,
              });
            }

            const day =
              dailyMap.get(key);

            day.total += 1;
            day.riskTotal +=
              score;
          }
        }
      });

      const trend = Array.from(
        dailyMap.values(),
      )
        .map((item) => ({
          date: item.date,
          total: item.total,
          averageRisk:
            item.total > 0
              ? Math.round(
                  item.riskTotal /
                    item.total,
                )
              : 0,
        }))
        .sort((a, b) =>
          a.date.localeCompare(
            b.date,
          ),
        )
        .slice(-7);

      const total =
        history.length;

      const classificationPercentage =
        Object.fromEntries(
          Object.entries(
            classificationCounts,
          ).map(
            ([key, value]) => [
              key,
              total > 0
                ? Math.round(
                    (value /
                      total) *
                      100,
                  )
                : 0,
            ],
          ),
        );

      return {
        classificationCounts,
        classificationPercentage,
        riskBuckets,
        trend,
        total,
      };
    }, [history]);

  const donutStyle =
    useMemo(() => {
      const total =
        historyMetrics.total;

      if (total === 0) {
        return {
          background:
            "conic-gradient(#e8edf4 0deg 360deg)",
        };
      }

      const low =
        historyMetrics
          .classificationCounts[
          "LOW RISK"
        ];

      const moderate =
        historyMetrics
          .classificationCounts[
          "MODERATE RISK"
        ];

      const suspicious =
        historyMetrics
          .classificationCounts[
          "SUSPICIOUS"
        ];

      const lowEnd =
        (low / total) *
        360;

      const moderateEnd =
        lowEnd +
        (moderate / total) *
          360;

      const suspiciousEnd =
        moderateEnd +
        (suspicious / total) *
          360;

      return {
        background: `conic-gradient(
          #5f9f78 0deg ${lowEnd}deg,
          #c7a35b ${lowEnd}deg ${moderateEnd}deg,
          #c47a55 ${moderateEnd}deg ${suspiciousEnd}deg,
          #bf5c63 ${suspiciousEnd}deg 360deg
        )`,
      };
    }, [historyMetrics]);

  const maximumTrendRisk =
    Math.max(
      100,
      ...historyMetrics.trend.map(
        (item) =>
          item.averageRisk,
      ),
    );

  const awarenessCards = [
    {
      id: "sender",
      number: "01",
      title: "Check the Sender",
      icon: "✉️",
      content:
        "Inspect the complete sender address instead of relying only on the display name. Look for unexpected domains, unusual spelling or suspicious formatting. An unfamiliar domain should be investigated, but it does not automatically prove that a message is phishing.",
      checks: [
        "Read the complete email address.",
        "Compare the domain with the expected organization.",
        "Look for unusual characters or lookalike spelling.",
        "Treat display-name trust with caution.",
      ],
    },
    {
      id: "urgency",
      number: "02",
      title: "Be Careful With Urgency",
      icon: "⏱️",
      content:
        "Phishing messages may use pressure, fear or deadlines to encourage quick decisions. A legitimate message can also be urgent, so urgency should be considered together with other signals.",
      checks: [
        "Look for immediate-action language.",
        "Notice threats of account loss or consequences.",
        "Do not let pressure bypass normal verification.",
        "Confirm important requests through a trusted channel.",
      ],
    },
    {
      id: "credentials",
      number: "03",
      title: "Protect Credentials",
      icon: "🔐",
      content:
        "Be cautious when an unexpected email asks for passwords, verification codes or sensitive personal information. Use the organization's known website or trusted support channel instead of relying on the email link.",
      checks: [
        "Do not disclose passwords by email.",
        "Be cautious about verification-code requests.",
        "Verify requests independently.",
        "Avoid entering sensitive data into unexpected pages.",
      ],
    },
    {
      id: "links",
      number: "04",
      title: "Inspect Links",
      icon: "🔗",
      content:
        "A URL can contain useful risk signals such as a raw IP address, unusual subdomains, suspicious keywords, shortening patterns or deceptive structure. HTTPS indicates encryption, not that a destination is trustworthy.",
      checks: [
        "Check the hostname carefully.",
        "Watch for raw IP addresses.",
        "Notice suspicious subdomain structure.",
        "Do not assume HTTPS means safe.",
      ],
    },
    {
      id: "attachments",
      number: "05",
      title: "Think Before Opening Attachments",
      icon: "📎",
      content:
        "Unexpected executables, scripts, suspicious archives and filenames with double extensions deserve extra review. This project analyzes attachment filenames statically and does not execute attachments.",
      checks: [
        "Be cautious with unexpected files.",
        "Watch executable and script extensions.",
        "Look for double extensions.",
        "Verify the sender and context first.",
      ],
    },
    {
      id: "context",
      number: "06",
      title: "Use Context",
      icon: "🧠",
      content:
        "No single phishing indicator guarantees that an email is malicious. Stronger analysis combines sender, subject, body, URL and attachment signals with the real-world context of the message.",
      checks: [
        "Consider several indicators together.",
        "Check whether the request makes sense.",
        "Look for false-positive possibilities.",
        "Use analyst judgment for final decisions.",
      ],
    },
  ];

  const responseActions = [
    "Pause before clicking links or opening unexpected attachments.",
    "Verify important requests through a known trusted channel.",
    "Avoid sharing passwords, verification codes or unnecessary personal information.",
    "Report suspicious messages through your organization's approved process.",
    "Keep the original message available for authorized security review.",
  ];

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-area">
          <p className="eyebrow">
            CYBERSECURITY PROJECT
          </p>

          <h1>
            Phishing Email Detection &
            Awareness Dashboard
          </h1>

          <p className="subtitle">
            Analyze email and URL indicators
            safely using static, explainable
            detection.
          </p>
        </div>

        <div className="backend-panel">
          <span className="status-label">
            Backend status
          </span>

          <span
            className={`backend-status ${
              backendStatus
                .toLowerCase()
                .includes("connected")
                ? "connected"
                : ""
            }`}
          >
            {backendStatus}
          </span>

          <button
            className="secondary-button"
            onClick={checkBackend}
            disabled={checkingBackend}
          >
            {checkingBackend
              ? "Checking..."
              : "Check Backend"}
          </button>
        </div>
      </header>

      <nav className="main-nav">
        <div className="nav-inner">
          <button
            className={
              activeSection ===
              "dashboard"
                ? "active"
                : ""
            }
            onClick={() =>
              scrollToSection(
                "dashboard",
              )
            }
          >
            Dashboard
          </button>

          <button
            className={
              activeSection ===
              "email-analyzer"
                ? "active"
                : ""
            }
            onClick={() =>
              scrollToSection(
                "email-analyzer",
              )
            }
          >
            Email Analyzer
          </button>

          <button
            className={
              activeSection ===
              "url-analyzer"
                ? "active"
                : ""
            }
            onClick={() =>
              scrollToSection(
                "url-analyzer",
              )
            }
          >
            URL Analyzer
          </button>

          <button
            className={
              activeSection ===
              "awareness"
                ? "active"
                : ""
            }
            onClick={() =>
              scrollToSection(
                "awareness",
              )
            }
          >
            Awareness
          </button>

          <button
            className={
              activeSection ===
              "history"
                ? "active"
                : ""
            }
            onClick={() =>
              scrollToSection(
                "history",
              )
            }
          >
            History
          </button>
        </div>
      </nav>

      <main className="main-content">
        <section
          id="dashboard"
          className="page-section"
        >
          <div className="hero-card">
            <div>
              <p className="section-tag">
                SECURITY OPERATIONS VIEW
              </p>

              <h2>
                Phishing detection at a glance
              </h2>

              <p>
                Review stored analysis activity,
                inspect common indicators and use
                the analyzer to support safe
                defensive triage.
              </p>
            </div>

            <div className="hero-badge">
              <span>DEFENSIVE</span>
              <strong>
                STATIC ANALYSIS
              </strong>
            </div>
          </div>

          <section className="stats-grid">
            <div className="stat-card">
              <span className="stat-label">
                Total Analyses
              </span>

              <strong>
                {loadingDashboard
                  ? "..."
                  : statsData.total}
              </strong>

              <small>
                Stored analysis records
              </small>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                Likely Phishing
              </span>

              <strong>
                {loadingDashboard
                  ? "..."
                  : statsData.phishing}
              </strong>

              <small>
                High-risk detections
              </small>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                Suspicious
              </span>

              <strong>
                {loadingDashboard
                  ? "..."
                  : statsData.suspicious}
              </strong>

              <small>
                Needs analyst review
              </small>
            </div>

            <div className="stat-card">
              <span className="stat-label">
                Average Risk
              </span>

              <strong>
                {loadingDashboard
                  ? "..."
                  : Math.round(
                      statsData.averageRisk,
                    )}
              </strong>

              <small>
                Risk score / 100
              </small>
            </div>
          </section>

          <section className="dashboard-section">
            <div className="section-heading">
              <div>
                <p className="section-tag">
                  ANALYTICS
                </p>

                <h2>
                  Live Security Analytics
                </h2>
              </div>

              <button
                className="secondary-button"
                onClick={
                  refreshDashboard
                }
                disabled={
                  loadingDashboard ||
                  loadingHistory
                }
              >
                {loadingDashboard ||
                loadingHistory
                  ? "Refreshing..."
                  : "Refresh Data"}
              </button>
            </div>

            <div className="chart-grid">
              <div className="chart-card">
                <div className="chart-header">
                  <div>
                    <h3>
                      Classification
                      Distribution
                    </h3>

                    <p>
                      Based on stored email
                      analyses
                    </p>
                  </div>
                </div>

                {historyMetrics.total >
                0 ? (
                  <div className="donut-layout">
                    <div
                      className="donut-chart"
                      style={
                        donutStyle
                      }
                    >
                      <div className="donut-center">
                        <strong>
                          {
                            historyMetrics.total
                          }
                        </strong>

                        <span>
                          Analyses
                        </span>
                      </div>
                    </div>

                    <div className="legend-list">
                      <div className="legend-item">
                        <span className="legend-color low" />

                        <div>
                          <strong>
                            Low Risk
                          </strong>

                          <span>
                            {
                              historyMetrics
                                .classificationCounts[
                                "LOW RISK"
                              ]
                            }{" "}
                            (
                            {
                              historyMetrics
                                .classificationPercentage[
                                "LOW RISK"
                              ]
                            }
                            %)
                          </span>
                        </div>
                      </div>

                      <div className="legend-item">
                        <span className="legend-color moderate" />

                        <div>
                          <strong>
                            Moderate
                          </strong>

                          <span>
                            {
                              historyMetrics
                                .classificationCounts[
                                "MODERATE RISK"
                              ]
                            }{" "}
                            (
                            {
                              historyMetrics
                                .classificationPercentage[
                                "MODERATE RISK"
                              ]
                            }
                            %)
                          </span>
                        </div>
                      </div>

                      <div className="legend-item">
                        <span className="legend-color suspicious" />

                        <div>
                          <strong>
                            Suspicious
                          </strong>

                          <span>
                            {
                              historyMetrics
                                .classificationCounts[
                                "SUSPICIOUS"
                              ]
                            }{" "}
                            (
                            {
                              historyMetrics
                                .classificationPercentage[
                                "SUSPICIOUS"
                              ]
                            }
                            %)
                          </span>
                        </div>
                      </div>

                      <div className="legend-item">
                        <span className="legend-color high" />

                        <div>
                          <strong>
                            High Risk
                          </strong>

                          <span>
                            {
                              historyMetrics
                                .classificationCounts[
                                "HIGH RISK"
                              ]
                            }{" "}
                            (
                            {
                              historyMetrics
                                .classificationPercentage[
                                "HIGH RISK"
                              ]
                            }
                            %)
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="chart-empty">
                    No analysis records are
                    available yet.
                  </div>
                )}
              </div>

              <div className="chart-card">
                <div className="chart-header">
                  <div>
                    <h3>
                      Risk Score Distribution
                    </h3>

                    <p>
                      Number of analyses in each
                      risk range
                    </p>
                  </div>
                </div>

                {historyMetrics.total >
                0 ? (
                  <div className="risk-distribution">
                    {Object.entries(
                      historyMetrics.riskBuckets,
                    ).map(
                      ([bucket, count]) => {
                        const percentage =
                          historyMetrics.total >
                          0
                            ? (count /
                                historyMetrics.total) *
                              100
                            : 0;

                        return (
                          <div
                            className="risk-bar-row"
                            key={bucket}
                          >
                            <div className="risk-bar-label">
                              <span>
                                {bucket}
                              </span>

                              <strong>
                                {count}
                              </strong>
                            </div>

                            <div className="risk-bar-track">
                              <div
                                className={`risk-bar-fill ${
                                  bucket ===
                                  "0–20"
                                    ? "low"
                                    : bucket ===
                                        "21–40"
                                      ? "moderate"
                                      : bucket ===
                                          "41–70"
                                        ? "suspicious"
                                        : "high"
                                }`}
                                style={{
                                  width: `${percentage}%`,
                                }}
                              />
                            </div>

                            <span className="risk-bar-percent">
                              {Math.round(
                                percentage,
                              )}
                              %
                            </span>
                          </div>
                        );
                      },
                    )}
                  </div>
                ) : (
                  <div className="chart-empty">
                    Analyze an email to
                    populate risk
                    distribution.
                  </div>
                )}
              </div>

              <div className="chart-card chart-card-wide">
                <div className="chart-header">
                  <div>
                    <h3>
                      Risk Trend
                    </h3>

                    <p>
                      Average risk score by
                      analysis date
                    </p>
                  </div>

                  <span className="chart-meta">
                    Last 7 active dates
                  </span>
                </div>

                {historyMetrics.trend
                  .length > 0 ? (
                  <div className="trend-chart">
                    <div className="trend-y-axis">
                      <span>100</span>
                      <span>75</span>
                      <span>50</span>
                      <span>25</span>
                      <span>0</span>
                    </div>

                    <div className="trend-area">
                      <div className="trend-grid-lines">
                        <span />
                        <span />
                        <span />
                        <span />
                        <span />
                      </div>

                      <div
                        className="trend-bars"
                        style={{
                          gridTemplateColumns: `repeat(${historyMetrics.trend.length}, minmax(45px, 1fr))`,
                        }}
                      >
                        {historyMetrics.trend.map(
                          (item) => {
                            const height =
                              Math.max(
                                4,
                                (item.averageRisk /
                                  maximumTrendRisk) *
                                  100,
                              );

                            return (
                              <div
                                className="trend-point"
                                key={item.date}
                              >
                                <div className="trend-value">
                                  {
                                    item.averageRisk
                                  }
                                </div>

                                <div
                                  className="trend-column"
                                  style={{
                                    height: `${height}%`,
                                  }}
                                />

                                <span className="trend-date">
                                  {new Date(
                                    `${item.date}T00:00:00`,
                                  ).toLocaleDateString(
                                    undefined,
                                    {
                                      day: "2-digit",
                                      month: "short",
                                    },
                                  )}
                                </span>

                                <small>
                                  {item.total}{" "}
                                  {item.total ===
                                  1
                                    ? "analysis"
                                    : "analyses"}
                                </small>
                              </div>
                            );
                          },
                        )}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="chart-empty">
                    Date-based trend data will
                    appear after analyses are
                    stored.
                  </div>
                )}
              </div>

              <div className="chart-card chart-card-wide">
                <div className="chart-header">
                  <div>
                    <h3>
                      Top Phishing Indicators
                    </h3>

                    <p>
                      Indicators recorded by the
                      backend
                    </p>
                  </div>
                </div>

                {normalizedIndicators.length >
                0 ? (
                  <div className="live-indicator-list">
                    {normalizedIndicators.map(
                      (indicator) => (
                        <div
                          className="live-indicator-item"
                          key={indicator.name}
                        >
                          <div className="indicator-info">
                            <span>
                              {indicator.name}
                            </span>

                            <strong>
                              {indicator.count}
                            </strong>
                          </div>

                          <div className="indicator-track">
                            <div
                              className="indicator-fill"
                              style={{
                                width: `${
                                  (indicator.count /
                                    maxIndicatorCount) *
                                  100
                                }%`,
                              }}
                            />
                          </div>
                        </div>
                      ),
                    )}
                  </div>
                ) : (
                  <div className="chart-empty">
                    No indicator data is
                    available yet.
                  </div>
                )}
              </div>
            </div>

            <div className="analytics-summary-strip">
              <div>
                <span>
                  Stored Analyses
                </span>

                <strong>
                  {historyMetrics.total}
                </strong>
              </div>

              <div>
                <span>
                  High Risk
                </span>

                <strong>
                  {
                    historyMetrics
                      .classificationCounts[
                      "HIGH RISK"
                    ]
                  }
                </strong>
              </div>

              <div>
                <span>
                  Suspicious
                </span>

                <strong>
                  {
                    historyMetrics
                      .classificationCounts[
                      "SUSPICIOUS"
                    ]
                  }
                </strong>
              </div>

              <div>
                <span>
                  Average Risk
                </span>

                <strong>
                  {Math.round(
                    statsData.averageRisk,
                  )}
                  /100
                </strong>
              </div>
            </div>
          </section>
        </section>

        <section
          id="email-analyzer"
          className="page-section"
        >
          <div className="section-heading">
            <div>
              <p className="section-tag">
                EMAIL ANALYZER
              </p>

              <h2>
                Analyze an Email
              </h2>
            </div>

            <span className="safe-chip">
              Synthetic / Safe Data
            </span>
          </div>

          <div className="content-grid">
            <div className="panel analyzer-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    Email Input
                  </h2>

                  <p className="panel-description">
                    Enter safe or authorized
                    sample content for analysis.
                  </p>
                </div>
              </div>

              <div className="upload-card">
                <div>
                  <p className="upload-label">
                    OPTIONAL EMAIL FILE
                  </p>

                  <h3>
                    Upload a safe .txt or .eml
                  </h3>

                  <p>
                    The browser reads the text,
                    extracts common email fields
                    and fills the analyzer for your
                    review.
                  </p>
                </div>

                <label className="upload-button">
                  {fileLoading
                    ? "Reading File..."
                    : "Choose Email File"}

                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".txt,.eml,text/plain,message/rfc822"
                    onChange={
                      handleFileUpload
                    }
                    disabled={fileLoading}
                  />
                </label>

                {fileStatus && (
                  <div
                    className={`file-status ${
                      fileStatus
                        .toLowerCase()
                        .includes(
                          "unable",
                        ) ||
                      fileStatus
                        .toLowerCase()
                        .includes(
                          "unsupported",
                        ) ||
                      fileStatus
                        .toLowerCase()
                        .includes(
                          "large",
                        )
                        ? "error"
                        : "success"
                    }`}
                  >
                    {fileStatus}
                  </div>
                )}
              </div>

              <div className="upload-safety-note">
                <strong>
                  Safety note:
                </strong>

                <span>
                  Only plain text metadata is extracted.
                  Uploaded content is not executed,
                  raw HTML is not rendered, and extracted
                  URLs are not visited automatically.
                </span>
              </div>

              <form
                onSubmit={handleAnalyze}
              >
                <div className="form-group">
                  <label htmlFor="sender">
                    Sender Email
                  </label>

                  <input
                    id="sender"
                    type="email"
                    placeholder="training@example.org"
                    value={form.sender}
                    onChange={(event) =>
                      updateField(
                        "sender",
                        event.target.value,
                      )
                    }
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="subject">
                    Subject
                  </label>

                  <input
                    id="subject"
                    type="text"
                    placeholder="Cybersecurity Workshop Reminder"
                    value={form.subject}
                    onChange={(event) =>
                      updateField(
                        "subject",
                        event.target.value,
                      )
                    }
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="body">
                    Email Body
                  </label>

                  <textarea
                    id="body"
                    rows="10"
                    placeholder="Paste the email body here or upload a safe .txt/.eml file..."
                    value={form.body}
                    onChange={(event) =>
                      updateField(
                        "body",
                        event.target.value,
                      )
                    }
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="urls">
                    URLs{" "}
                    <span className="optional">
                      (one per line)
                    </span>
                  </label>

                  <textarea
                    id="urls"
                    rows="4"
                    placeholder="https://example.org/workshop"
                    value={form.urls}
                    onChange={(event) =>
                      updateField(
                        "urls",
                        event.target.value,
                      )
                    }
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="attachment">
                    Attachment Name{" "}
                    <span className="optional">
                      (optional)
                    </span>
                  </label>

                  <input
                    id="attachment"
                    type="text"
                    placeholder="document.pdf"
                    value={
                      form.attachment_name
                    }
                    onChange={(event) =>
                      updateField(
                        "attachment_name",
                        event.target.value,
                      )
                    }
                  />
                </div>

                {error && (
                  <div className="error-box">
                    <strong>
                      Request Error
                    </strong>

                    <span>
                      {error}
                    </span>
                  </div>
                )}

                <div className="form-actions">
                  <button
                    className="primary-button"
                    type="submit"
                    disabled={
                      analyzing ||
                      fileLoading
                    }
                  >
                    {analyzing
                      ? "Analyzing..."
                      : "Analyze Email"}
                  </button>

                  <button
                    className="secondary-button"
                    type="button"
                    onClick={
                      clearAnalyzer
                    }
                    disabled={
                      analyzing ||
                      fileLoading
                    }
                  >
                    Clear
                  </button>
                </div>
              </form>
            </div>

            <div className="panel result-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    Risk Analysis
                  </h2>

                  <p className="panel-description">
                    Explainable result returned by
                    FastAPI.
                  </p>
                </div>
              </div>

              {!resultData && (
                <div className="empty-result">
                  <div className="empty-icon">
                    🔍
                  </div>

                  <h3>
                    No analysis yet
                  </h3>

                  <p>
                    Enter an email or load a safe
                    file, then click{" "}
                    <strong>
                      Analyze Email
                    </strong>{" "}
                    to view the detection result.
                  </p>
                </div>
              )}

              {resultData && (
                <div className="result-content">
                  <div
                    className={`score-card ${classificationClass}`}
                  >
                    <div className="score-ring">
                      <strong>
                        {resultData.score}
                      </strong>

                      <span>
                        /100
                      </span>
                    </div>

                    <div>
                      <span className="result-label">
                        Risk Score
                      </span>

                      <h3>
                        {
                          resultData.classification
                        }
                      </h3>
                    </div>
                  </div>

                  <div className="score-bar">
                    <div
                      className={`score-progress ${classificationClass}`}
                      style={{
                        width: `${resultData.score}%`,
                      }}
                    />
                  </div>

                  {resultData.why && (
                    <div className="result-section">
                      <h3>
                        Why this result?
                      </h3>

                      <p>
                        {resultData.why}
                      </p>
                    </div>
                  )}

                  <div className="result-section">
                    <h3>
                      Detected Findings
                    </h3>

                    {resultData.findings
                      .length > 0 ? (
                      <div className="finding-list">
                        {resultData.findings.map(
                          (
                            finding,
                            index,
                          ) => (
                            <div
                              className="finding-item"
                              key={`${finding}-${index}`}
                            >
                              <span className="finding-dot" />

                              <span>
                                {finding}
                              </span>
                            </div>
                          ),
                        )}
                      </div>
                    ) : (
                      <p className="muted">
                        No individual findings were
                        returned by the API.
                      </p>
                    )}
                  </div>

                  <div className="result-section">
                    <h3>
                      Recommendations
                    </h3>

                    {resultData
                      .recommendations
                      .length > 0 ? (
                      <div className="recommendation-list">
                        {resultData.recommendations.map(
                          (
                            item,
                            index,
                          ) => (
                            <div
                              className="recommendation-item"
                              key={`${item}-${index}`}
                            >
                              <span>
                                {index +
                                  1}
                              </span>

                              <p>
                                {item}
                              </p>
                            </div>
                          ),
                        )}
                      </div>
                    ) : (
                      <p className="muted">
                        No recommendation list was
                        returned by the API.
                      </p>
                    )}
                  </div>

                  <details className="technical-response">
                    <summary>
                      View API response
                    </summary>

                    <pre>
                      {JSON.stringify(
                        result,
                        null,
                        2,
                      )}
                    </pre>
                  </details>
                </div>
              )}
            </div>
          </div>
        </section>

        <section
          id="url-analyzer"
          className="page-section"
        >
          <div className="section-heading">
            <div>
              <p className="section-tag">
                STATIC URL ANALYSIS
              </p>

              <h2>
                Analyze a Suspicious URL
              </h2>
            </div>

            <span className="safe-chip">
              No URL is opened or visited
            </span>
          </div>

          <div className="url-panel">
            <div className="url-form-column">
              <form
                onSubmit={analyzeUrl}
              >
                <div className="form-group">
                  <label htmlFor="url-input">
                    URL to Analyze
                  </label>

                  <input
                    id="url-input"
                    type="text"
                    placeholder="http://198.51.100.10/verify-account"
                    value={urlInput}
                    onChange={(event) =>
                      setUrlInput(
                        event.target.value,
                      )
                    }
                  />

                  <p className="field-help">
                    Use a fictional, authorized or
                    reserved example URL. This tool
                    performs static inspection only.
                  </p>
                </div>

                {urlError && (
                  <div className="error-box">
                    <strong>
                      URL Analysis Error
                    </strong>

                    <span>
                      {urlError}
                    </span>
                  </div>
                )}

                <div className="form-actions">
                  <button
                    className="primary-button"
                    type="submit"
                    disabled={
                      urlAnalyzing
                    }
                  >
                    {urlAnalyzing
                      ? "Analyzing URL..."
                      : "Analyze URL"}
                  </button>

                  <button
                    className="secondary-button"
                    type="button"
                    onClick={
                      clearUrlAnalyzer
                    }
                    disabled={
                      urlAnalyzing
                    }
                  >
                    Clear
                  </button>
                </div>
              </form>

              <div className="safe-example-box">
                <span>
                  SAFE DEMONSTRATION EXAMPLE
                </span>

                <code>
                  http://198.51.100.10/verify-account
                </code>

                <button
                  className="example-button"
                  type="button"
                  onClick={() =>
                    setUrlInput(
                      "http://198.51.100.10/verify-account",
                    )
                  }
                >
                  Use Example
                </button>
              </div>
            </div>

            <div className="url-result-column">
              {!urlResultData ? (
                <div className="url-empty">
                  <div className="empty-icon">
                    🔗
                  </div>

                  <h3>
                    No URL analysis yet
                  </h3>

                  <p>
                    Enter a safe example URL and run
                    static analysis to see hostname,
                    path, protocol and other indicators.
                  </p>
                </div>
              ) : (
                <div className="url-result-content">
                  <div
                    className={`score-card ${urlClassificationClass}`}
                  >
                    <div className="score-ring">
                      <strong>
                        {
                          urlResultData.score
                        }
                      </strong>

                      <span>
                        /100
                      </span>
                    </div>

                    <div>
                      <span className="result-label">
                        URL Risk Score
                      </span>

                      <h3>
                        {
                          urlResultData.classification
                        }
                      </h3>
                    </div>
                  </div>

                  <div className="score-bar">
                    <div
                      className={`score-progress ${urlClassificationClass}`}
                      style={{
                        width: `${urlResultData.score}%`,
                      }}
                    />
                  </div>

                  <div className="url-indicator-grid">
                    <div className="url-indicator-card">
                      <span>
                        Scheme
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .scheme
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        Hostname
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .hostname
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        Path
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .path
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        URL Length
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .urlLength
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        Hostname Length
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .hostnameLength
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        Subdomains
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .subdomainCount
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        Raw IP
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .hasIpUrl
                            ? "YES"
                            : "NO"
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        Shortener Pattern
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .hasShortenedUrlPattern
                            ? "YES"
                            : "NO"
                        }
                      </strong>
                    </div>

                    <div className="url-indicator-card">
                      <span>
                        HTTPS
                      </span>

                      <strong>
                        {
                          urlResultData
                            .indicators
                            .https
                            ? "YES"
                            : "NO"
                        }
                      </strong>
                    </div>
                  </div>

                  <div className="result-section">
                    <h3>
                      URL Findings
                    </h3>

                    {urlResultData
                      .findings.length > 0 ? (
                      <div className="finding-list">
                        {urlResultData.findings.map(
                          (
                            finding,
                            index,
                          ) => (
                            <div
                              className="finding-item"
                              key={`${finding}-${index}`}
                            >
                              <span className="finding-dot" />

                              <span>
                                {finding}
                              </span>
                            </div>
                          ),
                        )}
                      </div>
                    ) : (
                      <p className="muted">
                        No individual URL findings were
                        returned by the API.
                      </p>
                    )}
                  </div>

                  <details className="technical-response">
                    <summary>
                      View URL API response
                    </summary>

                    <pre>
                      {JSON.stringify(
                        urlResult,
                        null,
                        2,
                      )}
                    </pre>
                  </details>
                </div>
              )}
            </div>
          </div>
        </section>

        <section
          id="awareness"
          className="page-section awareness-page"
        >
          <div className="awareness-hero">
            <div>
              <p className="section-tag">
                PHISHING AWARENESS CENTER
              </p>

              <h2>
                How to Spot a Phishing Email
              </h2>

              <p>
                Phishing detection is not only a
                technical problem. Good security
                decisions also depend on recognizing
                social engineering signals and verifying
                unexpected requests.
              </p>
            </div>

            <div className="awareness-score">
              <span>
                REMEMBER
              </span>

              <strong>
                STOP • CHECK • VERIFY
              </strong>
            </div>
          </div>

          <div className="awareness-grid-full">
            {awarenessCards.map(
              (card) => {
                const isOpen =
                  awarenessOpen ===
                  card.id;

                return (
                  <article
                    className={`awareness-learning-card ${
                      isOpen
                        ? "open"
                        : ""
                    }`}
                    key={card.id}
                  >
                    <button
                      className="awareness-card-header"
                      onClick={() =>
                        setAwarenessOpen(
                          isOpen
                            ? null
                            : card.id,
                        )
                      }
                    >
                      <div className="awareness-icon">
                        {card.icon}
                      </div>

                      <div className="awareness-card-title">
                        <span>
                          {card.number}
                        </span>

                        <h3>
                          {card.title}
                        </h3>
                      </div>

                      <span className="expand-icon">
                        {isOpen
                          ? "−"
                          : "+"}
                      </span>
                    </button>

                    {isOpen && (
                      <div className="awareness-card-body">
                        <p>
                          {card.content}
                        </p>

                        <h4>
                          Quick Checks
                        </h4>

                        <div className="awareness-checks">
                          {card.checks.map(
                            (check) => (
                              <div
                                className="awareness-check"
                                key={check}
                              >
                                <span>
                                  ✓
                                </span>

                                <p>
                                  {check}
                                </p>
                              </div>
                            ),
                          )}
                        </div>
                      </div>
                    )}
                  </article>
                );
              },
            )}
          </div>

          <div className="before-click-panel">
            <div>
              <p className="section-tag">
                BEFORE YOU CLICK
              </p>

              <h3>
                Use a verification mindset
              </h3>

              <p>
                When something feels urgent or
                unusual, slow down and independently
                confirm the request.
              </p>
            </div>

            <div className="before-click-steps">
              <div>
                <span>1</span>

                <strong>
                  Pause
                </strong>

                <p>
                  Do not act immediately under
                  pressure.
                </p>
              </div>

              <div>
                <span>2</span>

                <strong>
                  Inspect
                </strong>

                <p>
                  Check sender, message, links
                  and files.
                </p>
              </div>

              <div>
                <span>3</span>

                <strong>
                  Verify
                </strong>

                <p>
                  Use a trusted communication
                  channel.
                </p>
              </div>

              <div>
                <span>4</span>

                <strong>
                  Report
                </strong>

                <p>
                  Follow your approved reporting
                  process.
                </p>
              </div>
            </div>
          </div>

          <div className="response-panel">
            <div>
              <p className="section-tag">
                RECOMMENDED ACTIONS
              </p>

              <h3>
                What should you do with a
                suspicious email?
              </h3>
            </div>

            <div className="response-actions">
              {responseActions.map(
                (action, index) => (
                  <div
                    className="response-action"
                    key={action}
                  >
                    <span>
                      {index + 1}
                    </span>

                    <p>
                      {action}
                    </p>
                  </div>
                ),
              )}
            </div>
          </div>

          <div className="awareness-disclaimer">
            <strong>
              Educational reminder:
            </strong>

            <span>
              Automated detection supports human review.
              No single indicator guarantees that a message
              is phishing, and a legitimate message can
              contain signals that resemble phishing.
            </span>
          </div>
        </section>

        <section
          id="history"
          className="page-section"
        >
          <div className="section-heading">
            <div>
              <p className="section-tag">
                ANALYSIS HISTORY
              </p>

              <h2>
                Recent Analyses
              </h2>
            </div>

            <span className="history-count">
              {history.length} record
              {history.length === 1
                ? ""
                : "s"}
            </span>
          </div>

          <div className="history-panel">
            {loadingHistory ? (
              <div className="history-empty">
                Loading analysis history...
              </div>
            ) : history.length ===
              0 ? (
              <div className="history-empty">
                <div className="empty-icon">
                  🗂️
                </div>

                <h3>
                  No stored analyses
                </h3>

                <p>
                  Your successful email analyses
                  will appear here after they are
                  saved by the backend.
                </p>
              </div>
            ) : (
              <div className="history-table-wrapper">
                <table className="history-table">
                  <thead>
                    <tr>
                      <th>
                        ID
                      </th>

                      <th>
                        Sender
                      </th>

                      <th>
                        Subject
                      </th>

                      <th>
                        Risk
                      </th>

                      <th>
                        Classification
                      </th>

                      <th>
                        Created
                      </th>

                      <th>
                        Action
                      </th>
                    </tr>
                  </thead>

                  <tbody>
                    {history.map(
                      (
                        item,
                        index,
                      ) => {
                        const analysisId =
                          firstDefined(
                            item?.id,
                            item?.analysis_id,
                          );

                        const sender =
                          firstDefined(
                            item?.sender,
                            item?.sender_email,
                            "Unknown",
                          );

                        const subject =
                          firstDefined(
                            item?.subject,
                            "No subject",
                          );

                        const score =
                          Number(
                            firstDefined(
                              item?.hybrid_score,
                              item?.risk_score,
                              item?.score,
                              item?.rule_score,
                              0,
                            ),
                          );

                        const classification =
                          String(
                            firstDefined(
                              item?.classification,
                              item?.risk_level,
                              "UNKNOWN",
                            ),
                          );

                        const createdAt =
                          firstDefined(
                            item?.created_at,
                            item?.timestamp,
                            item?.analyzed_at,
                            "",
                          );

                        return (
                          <tr
                            key={
                              analysisId ??
                              index
                            }
                          >
                            <td>
                              #
                              {analysisId ??
                                index +
                                  1}
                            </td>

                            <td className="history-sender">
                              {sender}
                            </td>

                            <td className="history-subject">
                              {subject}
                            </td>

                            <td>
                              <span className="history-score">
                                {score}/100
                              </span>
                            </td>

                            <td>
                              <span
                                className={`history-classification ${
                                  classification
                                    .toLowerCase()
                                    .includes(
                                      "high",
                                    )
                                    ? "danger"
                                    : classification
                                        .toLowerCase()
                                        .includes(
                                          "suspicious",
                                        )
                                      ? "warning"
                                      : classification
                                          .toLowerCase()
                                          .includes(
                                            "low",
                                          )
                                        ? "safe"
                                        : "neutral"
                                }`}
                              >
                                {classification}
                              </span>
                            </td>

                            <td>
                              {createdAt
                                ? new Date(
                                    createdAt,
                                  ).toLocaleString()
                                : "—"}
                            </td>

                            <td>
                              <button
                                className="delete-button"
                                onClick={() =>
                                  deleteAnalysis(
                                    analysisId,
                                  )
                                }
                                disabled={
                                  analysisId ===
                                    undefined ||
                                  deletingId ===
                                    analysisId
                                }
                              >
                                {deletingId ===
                                analysisId
                                  ? "Deleting..."
                                  : "Delete"}
                              </button>
                            </td>
                          </tr>
                        );
                      },
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </section>
      </main>

      <footer className="footer">
        <div>
          <strong>
            Phishing Email Detection &
            Awareness Dashboard
          </strong>

          <span>
            Educational and defensive cybersecurity
            project
          </span>
        </div>

        <button
          className="back-top-button"
          onClick={() =>
            scrollToSection(
              "dashboard",
            )
          }
        >
          ↑ Back to Dashboard
        </button>
      </footer>
    </div>
  );
}

export default App;