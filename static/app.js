const initializeSkuPickers = (root = document) => {
  root.querySelectorAll("[data-sku-picker]").forEach((picker) => {
    if (picker.dataset.initialized === "true") return;
    picker.dataset.initialized = "true";

    const hiddenInput = picker.querySelector("[data-sku-picker-value]");
    const searchInput = picker.querySelector("[data-sku-picker-input]");
    if (!hiddenInput || !searchInput) return;

    const listId = searchInput.getAttribute("list");
    const dataList = listId ? document.getElementById(listId) : null;
    if (!dataList) return;

    const syncValue = () => {
      const currentValue = searchInput.value.trim();
      const matchedOption = Array.from(dataList.options).find((option) => option.value === currentValue);
      hiddenInput.value = matchedOption ? matchedOption.dataset.skuId || "" : "";

      if (searchInput.hasAttribute("data-sku-picker-required")) {
        if (!currentValue) {
          searchInput.setCustomValidity("请选择 SKU");
        } else if (!hiddenInput.value) {
          searchInput.setCustomValidity("请从建议列表中选择 SKU");
        } else {
          searchInput.setCustomValidity("");
        }
      } else if (currentValue && !hiddenInput.value) {
        searchInput.setCustomValidity("请从建议列表中选择 SKU");
      } else {
        searchInput.setCustomValidity("");
      }
    };

    searchInput.addEventListener("input", syncValue);
    searchInput.addEventListener("change", syncValue);
    searchInput.addEventListener("blur", syncValue);

    const form = picker.closest("form");
    if (form && !form.dataset.skuPickerBound) {
      form.dataset.skuPickerBound = "true";
      form.addEventListener("submit", () => {
        form.querySelectorAll("[data-sku-picker]").forEach((item) => {
          const trigger = item.querySelector("[data-sku-picker-input]");
          if (trigger) trigger.dispatchEvent(new Event("change", { bubbles: true }));
        });
      });
    }

    syncValue();
  });
};

document.querySelectorAll("[data-prefix]").forEach((box) => {
  const rows = box.querySelector("[data-rows]");
  const template = box.querySelector("[data-row-template]");
  const addButton = box.querySelector("[data-add-row]");
  if (!rows || !template || !addButton) return;

  const addRow = () => {
    const fragment = template.content.cloneNode(true);
    initializeSkuPickers(fragment);
    rows.appendChild(fragment);
  };

  addButton.addEventListener("click", addRow);
  rows.addEventListener("click", (event) => {
    if (event.target.matches("[data-remove-row]")) {
      const row = event.target.closest(".dynamic-row");
      if (row) row.remove();
    }
  });

  if (!rows.querySelector(".dynamic-row")) {
    addRow();
  }
});

initializeSkuPickers();

const warehousePostalMapNode = document.getElementById("warehouse-postal-map");
let warehousePostalMap = {};
if (warehousePostalMapNode) {
  try {
    warehousePostalMap = JSON.parse(warehousePostalMapNode.textContent || "{}");
  } catch (_error) {
    warehousePostalMap = {};
  }
}

const syncFreightPostalCode = (warehouseInput) => {
  const row = warehouseInput.closest("tr");
  const postalInput = row?.querySelector('input[name="quote_postal_code"]');
  if (!postalInput) return;
  const warehouseCode = (warehouseInput.value || "").trim().toUpperCase();
  const postalCode = warehousePostalMap[warehouseCode];
  if (!postalCode) {
    if (postalInput.dataset.autoFilled === "true") {
      postalInput.value = "";
      postalInput.dataset.autoFilled = "false";
    }
    return;
  }
  if (postalInput.value.trim() && postalInput.dataset.autoFilled !== "true") return;
  postalInput.value = postalCode;
  postalInput.dataset.autoFilled = "true";
};

document.querySelectorAll('input[name="quote_warehouse_code"]').forEach((input) => {
  input.addEventListener("input", () => syncFreightPostalCode(input));
  input.addEventListener("change", () => syncFreightPostalCode(input));
  syncFreightPostalCode(input);
});

document.querySelectorAll('input[name="quote_postal_code"]').forEach((input) => {
  input.addEventListener("input", () => {
    input.dataset.autoFilled = input.value.trim() ? "false" : "true";
  });
});

const copyDimensionsToggle = document.querySelector("[data-copy-dimensions-all]");
const copyDimensionsControl = copyDimensionsToggle?.closest(".freight-dimension-copy");
const freightInputTable = document.querySelector(".freight-input-table");
const dimensionFieldNames = ["quote_length_cm", "quote_width_cm", "quote_height_cm"];

const rowHasFreightItem = (row) => {
  return ["quote_warehouse_code", "quote_postal_code", "quote_weight_kg"].some((name) => {
    const input = row.querySelector(`input[name="${name}"]`);
    return Boolean(input?.value.trim());
  });
};

const getDimensionSourceRow = () => {
  const rows = Array.from(freightInputTable?.querySelectorAll("tbody tr") || []);
  return rows.find((row) =>
    dimensionFieldNames.some((name) => row.querySelector(`input[name="${name}"]`)?.value.trim())
  );
};

const applyDimensionsToFreightRows = () => {
  if (!copyDimensionsToggle?.checked || !freightInputTable) return;
  const sourceRow = getDimensionSourceRow();
  if (!sourceRow) return;
  const sourceValues = Object.fromEntries(
    dimensionFieldNames.map((name) => [name, sourceRow.querySelector(`input[name="${name}"]`)?.value || ""])
  );
  if (!Object.values(sourceValues).some((value) => value.trim())) return;

  const rows = Array.from(freightInputTable.querySelectorAll("tbody tr"));
  const sourceIndex = rows.indexOf(sourceRow);
  rows.forEach((row, index) => {
    if (row === sourceRow) return;
    if (index < sourceIndex && !rowHasFreightItem(row)) return;
    dimensionFieldNames.forEach((name) => {
      const input = row.querySelector(`input[name="${name}"]`);
      if (input) input.value = sourceValues[name];
    });
  });
};

if (copyDimensionsToggle && freightInputTable) {
  copyDimensionsToggle.addEventListener("change", applyDimensionsToFreightRows);
  copyDimensionsControl?.addEventListener("click", () => {
    window.setTimeout(applyDimensionsToFreightRows, 0);
  });
  freightInputTable.addEventListener("input", (event) => {
    if (!copyDimensionsToggle.checked) return;
    if (dimensionFieldNames.includes(event.target?.name) || ["quote_warehouse_code", "quote_postal_code", "quote_weight_kg"].includes(event.target?.name)) {
      applyDimensionsToFreightRows();
    }
  });
  freightInputTable.addEventListener("change", applyDimensionsToFreightRows);
}

document.querySelectorAll(".interactive-table tbody").forEach((tbody) => {
  tbody.addEventListener("click", (event) => {
    const row = event.target.closest("tr");
    if (!row) return;

    tbody.querySelectorAll("tr.row-selected").forEach((selectedRow) => {
      if (selectedRow !== row) selectedRow.classList.remove("row-selected");
    });

    row.classList.toggle("row-selected");
  });
});

document.querySelectorAll("[data-auth-search]").forEach((input) => {
  input.addEventListener("input", () => {
    const keyword = input.value.trim().toLowerCase();
    const authCard = input.closest(".sku-auth-body");
    if (!authCard) return;

    authCard.querySelectorAll("[data-auth-user]").forEach((item) => {
      const name = item.getAttribute("data-auth-user") || "";
      item.hidden = keyword ? !name.includes(keyword) : false;
    });
  });
});

const batchSkuCheckboxes = Array.from(document.querySelectorAll("[data-batch-sku]"));
const batchCountLabels = Array.from(document.querySelectorAll("[data-batch-count]"));
const batchToggleButtons = Array.from(document.querySelectorAll("[data-batch-toggle]"));
const batchBoxCountInput = document.querySelector("[data-batch-box-count]");
const batchPerBoxOutputs = Array.from(document.querySelectorAll("[data-batch-per-box-output]"));
const shipmentQuantityInputs = Array.from(document.querySelectorAll("[data-shipment-quantity]"));

const formatBatchPerBoxValue = (value) => {
  if (!Number.isFinite(value) || value <= 0) {
    return "0";
  }
  if (Number.isInteger(value)) {
    return `${value}`;
  }
  return value.toFixed(2).replace(/\.?0+$/, "");
};

const getAutoShipmentQuantity = (input, boxCount) => {
  const suggestedQty = Math.max(Number.parseInt(input.dataset.suggestedQty || "0", 10) || 0, 0);
  const warehouseQty = Math.max(Number.parseInt(input.dataset.warehouseQty || "0", 10) || 0, 0);
  if (boxCount <= 0 || suggestedQty <= 0 || warehouseQty <= 0) {
    return 0;
  }
  const roundedUpQuantity = Math.ceil(suggestedQty / boxCount) * boxCount;
  if (roundedUpQuantity <= warehouseQty) {
    return roundedUpQuantity;
  }
  return Math.floor(warehouseQty / boxCount) * boxCount;
};

if (batchSkuCheckboxes.length) {
  const autoFillShipmentQuantities = () => {
    const boxCount = Math.max(Number.parseInt(batchBoxCountInput?.value || "0", 10) || 0, 0);
    shipmentQuantityInputs.forEach((input) => {
      input.value = String(getAutoShipmentQuantity(input, boxCount));
    });
  };

  const syncBatchPerBox = () => {
    const boxCount = Math.max(Number.parseInt(batchBoxCountInput?.value || "0", 10) || 0, 0);
    let totalQuantity = 0;

    shipmentQuantityInputs.forEach((input) => {
      const quantity = Math.max(Number.parseInt(input.value || "0", 10) || 0, 0);
      const rowCell = input.closest("tr")?.querySelector("[data-per-box-row]");
      const shouldWarnBox = boxCount > 0 && quantity > 0 && quantity % boxCount !== 0;
      const perBoxValue = boxCount > 0 ? quantity / boxCount : 0;
      if (rowCell) {
        rowCell.textContent = formatBatchPerBoxValue(perBoxValue);
      }
      input.classList.toggle("input-error", shouldWarnBox);
      if (shouldWarnBox) {
        input.setCustomValidity(`当前数量 ${quantity} 不能被箱数 ${boxCount} 整除`);
      } else {
        input.setCustomValidity("");
      }
      totalQuantity += quantity;
    });

    const batchPerBoxValue = boxCount > 0 ? totalQuantity / boxCount : 0;
    batchPerBoxOutputs.forEach((output) => {
      output.value = formatBatchPerBoxValue(batchPerBoxValue);
    });
  };

  const syncBatchCount = () => {
    const checkedCount = batchSkuCheckboxes.filter((item) => item.checked).length;
    batchCountLabels.forEach((label) => {
      label.textContent = `已选 ${checkedCount} 个 SKU`;
    });
    batchToggleButtons.forEach((button) => {
      if (button.tagName === "INPUT") {
        button.checked = checkedCount > 0 && checkedCount === batchSkuCheckboxes.length;
        button.indeterminate = checkedCount > 0 && checkedCount < batchSkuCheckboxes.length;
      } else {
        button.textContent = checkedCount === batchSkuCheckboxes.length ? "取消全选当前页" : "全选当前页";
      }
    });
    syncBatchPerBox();
  };

  batchSkuCheckboxes.forEach((checkbox) => {
    checkbox.addEventListener("change", syncBatchCount);
  });

  shipmentQuantityInputs.forEach((input) => {
    input.addEventListener("input", syncBatchPerBox);
  });

  if (batchBoxCountInput) {
    batchBoxCountInput.addEventListener("input", () => {
      autoFillShipmentQuantities();
      syncBatchPerBox();
    });
  }

  batchToggleButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const shouldSelectAll = batchSkuCheckboxes.some((item) => !item.checked);
      batchSkuCheckboxes.forEach((item) => {
        item.checked = shouldSelectAll;
      });
      syncBatchCount();
    });
  });

  autoFillShipmentQuantities();
  syncBatchCount();
}

const scannerModal = document.querySelector("[data-barcode-scanner]");
const scannerVideo = scannerModal?.querySelector("[data-scanner-video]");
const scannerStatus = scannerModal?.querySelector("[data-scanner-status]");
let scannerStream = null;
let scannerAnimationId = null;
let currentScanTarget = null;
let barcodeDetector = null;
const isBarcodeDetectorAvailable = "BarcodeDetector" in window;

const supportsLiveBarcodeScan = () => isBarcodeDetectorAvailable && !!navigator.mediaDevices?.getUserMedia;

const ensureBarcodeDetector = () => {
  if (!isBarcodeDetectorAvailable) return null;
  if (!barcodeDetector) {
    barcodeDetector = new window.BarcodeDetector({
      formats: ["code_128", "code_39", "ean_13", "ean_8", "upc_a", "upc_e", "itf", "codabar"],
    });
  }
  return barcodeDetector;
};

const fillScannedValue = (targetInput, value) => {
  if (!targetInput || !value) return;
  targetInput.value = value;
  targetInput.dispatchEvent(new Event("input", { bubbles: true }));
};

const stopBarcodeScanner = () => {
  if (scannerAnimationId) {
    cancelAnimationFrame(scannerAnimationId);
    scannerAnimationId = null;
  }
  if (scannerStream) {
    scannerStream.getTracks().forEach((track) => track.stop());
    scannerStream = null;
  }
  if (scannerVideo) {
    scannerVideo.srcObject = null;
  }
  if (scannerModal) {
    scannerModal.hidden = true;
  }
  currentScanTarget = null;
};

const scanBarcodeFrame = async () => {
  if (!barcodeDetector || !scannerVideo || !currentScanTarget || scannerVideo.readyState < 2) {
    scannerAnimationId = requestAnimationFrame(scanBarcodeFrame);
    return;
  }

  try {
    const barcodes = await barcodeDetector.detect(scannerVideo);
    if (barcodes.length) {
      const value = (barcodes[0].rawValue || "").trim();
      if (value) {
        fillScannedValue(currentScanTarget, value);
        stopBarcodeScanner();
        return;
      }
    }
  } catch (_error) {
    if (scannerStatus) {
      scannerStatus.textContent = "扫码识别失败，请调整距离、角度或光线后重试。";
    }
  }

  scannerAnimationId = requestAnimationFrame(scanBarcodeFrame);
};

const openBarcodeScanner = async (targetInput) => {
  if (!scannerModal || !scannerVideo || !targetInput) return;
  if (!supportsLiveBarcodeScan()) {
    window.alert("当前环境不支持实时摄像头扫码。你可以改用旁边的“拍照识别”，或者在 HTTPS 环境下用手机 Chrome 打开。");
    return;
  }

  try {
    ensureBarcodeDetector();
    currentScanTarget = targetInput;
    scannerModal.hidden = false;
    if (scannerStatus) {
      scannerStatus.textContent = "请将条形码放在取景框中央。";
    }
    scannerStream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: "environment" },
      },
      audio: false,
    });
    scannerVideo.srcObject = scannerStream;
    await scannerVideo.play();
    scannerAnimationId = requestAnimationFrame(scanBarcodeFrame);
  } catch (_error) {
    stopBarcodeScanner();
    window.alert("无法打开摄像头，请检查浏览器权限，或改用“拍照识别”。");
  }
};

const detectBarcodeFromImageFile = async (file, targetInput) => {
  if (!targetInput || !file) return;
  if (!isBarcodeDetectorAvailable) {
    window.alert("当前浏览器不支持图片条码识别。建议使用手机 Chrome，并尽量通过 HTTPS 打开系统。");
    return;
  }

  try {
    const detector = ensureBarcodeDetector();
    const bitmap = await createImageBitmap(file);
    const barcodes = await detector.detect(bitmap);
    if (typeof bitmap.close === "function") {
      bitmap.close();
    }
    if (!barcodes.length) {
      window.alert("没有识别到条形码，请换一张更清晰、只包含一个条码的照片再试。");
      return;
    }
    const value = (barcodes[0].rawValue || "").trim();
    if (!value) {
      window.alert("识别到了条码，但没有读取到内容，请换一张更清晰的照片再试。");
      return;
    }
    fillScannedValue(targetInput, value);
  } catch (_error) {
    window.alert("图片识别失败，请换一张更清晰的照片，或先手动输入。");
  }
};

document.querySelectorAll("[data-open-barcode-scanner]").forEach((button) => {
  button.addEventListener("click", () => {
    const wrapper = button.closest(".scan-input-group");
    const targetInput = wrapper?.querySelector("[data-scan-target-input]");
    openBarcodeScanner(targetInput);
  });
});

document.querySelectorAll("[data-open-barcode-image]").forEach((button) => {
  button.addEventListener("click", () => {
    const wrapper = button.closest(".scan-input-group");
    const targetInput = wrapper?.querySelector("[data-scan-target-input]");
    const imageInput = wrapper?.querySelector("[data-barcode-image-input]");
    if (!targetInput || !imageInput) return;
    imageInput.value = "";
    imageInput.onchange = async () => {
      const file = imageInput.files?.[0];
      await detectBarcodeFromImageFile(file, targetInput);
      imageInput.value = "";
    };
    imageInput.click();
  });
});

scannerModal?.querySelectorAll("[data-close-barcode-scanner]").forEach((button) => {
  button.addEventListener("click", stopBarcodeScanner);
});

const shipmentForm = document.querySelector("[data-shipment-form]");
const shipmentBox = document.querySelector("[data-shipment-box]");
const shipmentAvailableDataEl = document.getElementById("shipment-available-data");
const shipmentAvailableData = shipmentAvailableDataEl ? JSON.parse(shipmentAvailableDataEl.textContent || "{}") : {};

if (shipmentForm && shipmentBox) {
  const rows = shipmentBox.querySelector("[data-shipment-rows]");
  const template = shipmentBox.querySelector("[data-shipment-row-template]");
  const addButtons = shipmentBox.querySelectorAll("[data-shipment-add-rows]");
  const boxCountInput = shipmentForm.querySelector("[data-shipment-box-count]");
  const perBoxTotalInput = shipmentForm.querySelector("[data-shipment-per-box-total]");
  const shipmentPrelockUrl = shipmentForm.dataset.shipmentPrelockUrl;
  const shipmentReleaseUrl = shipmentForm.dataset.shipmentReleaseUrl;
  const shipmentCsrfToken = shipmentForm.dataset.csrfToken || "";

  const syncPrelockButton = (row, locked, lockedCode = "") => {
    const button = row.querySelector("[data-shipment-prelock]");
    if (!button) return;
    button.dataset.locked = locked ? "true" : "false";
    button.dataset.lockedCode = locked ? lockedCode : "";
    button.textContent = locked ? "已预锁" : "预锁定";
    button.classList.toggle("warn", locked);
  };

  const releaseShipmentPrelock = async (row, { silent = false } = {}) => {
    const button = row.querySelector("[data-shipment-prelock]");
    const externalCode = button?.dataset.lockedCode || (row.querySelector("[data-shipment-external-sku]")?.value || "").trim();
    if (!externalCode || !shipmentReleaseUrl) {
      syncPrelockButton(row, false);
      return true;
    }
    try {
      const response = await fetch(shipmentReleaseUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
          "X-CSRF-Token": shipmentCsrfToken,
        },
        body: new URLSearchParams({ external_sku_code: externalCode }).toString(),
        credentials: "same-origin",
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) {
        if (!silent) window.alert(payload.message || "取消预锁失败，请重试。");
        return false;
      }
      syncPrelockButton(row, false);
      return true;
    } catch (_error) {
      if (!silent) window.alert("取消预锁失败，请检查网络后重试。");
      return false;
    }
  };

  const updateShipmentRow = (row, { showAlerts = false } = {}) => {
    const externalInput = row.querySelector("[data-shipment-external-sku]");
    const quantityInput = row.querySelector("[data-shipment-quantity]");
    const perBoxInput = row.querySelector("[data-shipment-per-box]");
    const availableLabel = row.querySelector("[data-shipment-available]");
    const boxCount = Math.max(parseInt(boxCountInput?.value || "0", 10) || 0, 0);
    const quantity = Math.max(parseInt(quantityInput?.value || "0", 10) || 0, 0);
    const externalCode = (externalInput?.value || "").trim();
    const available = externalCode ? parseInt(shipmentAvailableData[externalCode] || "0", 10) || 0 : 0;
    const shouldWarnStock = !!externalCode && quantity > available;
    const shouldWarnBox = boxCount > 0 && quantity > 0 && quantity % boxCount !== 0;

    if (availableLabel) {
      availableLabel.textContent = externalCode ? `可用 ${available}` : "可用 -";
      availableLabel.classList.toggle("warn", shouldWarnStock);
    }

    if (quantityInput) {
      quantityInput.classList.toggle("input-error", shouldWarnStock || shouldWarnBox);
      if (shouldWarnStock) {
        quantityInput.setCustomValidity(`库存不足，当前实时可用库存只有 ${available}`);
      } else if (shouldWarnBox) {
        quantityInput.setCustomValidity(`当前数量 ${quantity} 不能被箱数 ${boxCount} 整除`);
      } else {
        quantityInput.setCustomValidity("");
      }
    }

    if (perBoxInput) {
      if (boxCount > 0 && quantity > 0 && !shouldWarnBox) {
        perBoxInput.value = String(quantity / boxCount);
      } else {
        perBoxInput.value = "";
      }
    }

    if (showAlerts && shouldWarnStock && row.dataset.stockWarned !== "true") {
      window.alert(`库存不足：${externalCode} 当前实时可用库存只有 ${available}`);
      row.dataset.stockWarned = "true";
    }
    if (!shouldWarnStock) {
      row.dataset.stockWarned = "false";
    }

    if (showAlerts && shouldWarnBox && row.dataset.boxWarned !== "true") {
      window.alert(`箱数不匹配：当前数量 ${quantity} 不能被箱数 ${boxCount} 整除`);
      row.dataset.boxWarned = "true";
    }
    if (!shouldWarnBox) {
      row.dataset.boxWarned = "false";
    }

    if (perBoxTotalInput) {
      const total = Array.from(rows?.querySelectorAll("[data-shipment-per-box]") || []).reduce((sum, input) => {
        return sum + (parseInt(input.value || "0", 10) || 0);
      }, 0);
      perBoxTotalInput.value = String(total);
    }
  };

  const bindShipmentRow = (row) => {
    row.querySelectorAll("[data-shipment-external-sku], [data-shipment-quantity]").forEach((input) => {
      input.addEventListener("input", async () => {
        if (row.querySelector("[data-shipment-prelock]")?.dataset.locked === "true") {
          await releaseShipmentPrelock(row, { silent: true });
        }
        updateShipmentRow(row, { showAlerts: false });
      });
      input.addEventListener("change", async () => {
        if (row.querySelector("[data-shipment-prelock]")?.dataset.locked === "true") {
          await releaseShipmentPrelock(row, { silent: true });
        }
        updateShipmentRow(row, { showAlerts: true });
      });
      input.addEventListener("blur", () => {
        updateShipmentRow(row, { showAlerts: true });
      });
    });
    row.querySelector("[data-shipment-prelock]")?.addEventListener("click", async () => {
      const button = row.querySelector("[data-shipment-prelock]");
      const externalCode = (row.querySelector("[data-shipment-external-sku]")?.value || "").trim();
      const quantity = Math.max(parseInt(row.querySelector("[data-shipment-quantity]")?.value || "0", 10) || 0, 0);
      if (button?.dataset.locked === "true") {
        await releaseShipmentPrelock(row);
        return;
      }
      if (!externalCode) {
        window.alert("请先选择店铺SKU。");
        return;
      }
      if (quantity <= 0) {
        window.alert("请先填写有效数量。");
        return;
      }
      updateShipmentRow(row, { showAlerts: true });
      if (!row.querySelector("[data-shipment-quantity]")?.checkValidity()) {
        row.querySelector("[data-shipment-quantity]")?.reportValidity();
        return;
      }
      try {
        const response = await fetch(shipmentPrelockUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-CSRF-Token": shipmentCsrfToken,
          },
          body: new URLSearchParams({ external_sku_code: externalCode, quantity: String(quantity) }).toString(),
          credentials: "same-origin",
        });
        const payload = await response.json();
        if (!response.ok || !payload.ok) {
          window.alert(payload.message || "预锁失败，请重试。");
          return;
        }
        syncPrelockButton(row, true, externalCode);
        window.alert(payload.message || "预锁成功。");
      } catch (_error) {
        window.alert("预锁失败，请检查网络后重试。");
      }
    });
    updateShipmentRow(row, { showAlerts: false });
    syncPrelockButton(
      row,
      row.querySelector("[data-shipment-prelock]")?.dataset.locked === "true",
      (row.querySelector("[data-shipment-external-sku]")?.value || "").trim(),
    );
  };

  rows?.querySelectorAll("[data-shipment-row]").forEach(bindShipmentRow);

  const appendShipmentRows = (count) => {
    if (!rows || !template) return;
    for (let i = 0; i < count; i += 1) {
      const fragment = template.content.cloneNode(true);
      const row = fragment.querySelector("[data-shipment-row]");
      if (row) bindShipmentRow(row);
      rows.appendChild(fragment);
    }
  };

  addButtons.forEach((button) => {
    button.addEventListener("click", () => {
      appendShipmentRows(Math.max(parseInt(button.dataset.shipmentAddRows || "1", 10) || 1, 1));
    });
  });

  rows?.addEventListener("click", (event) => {
    if (event.target.matches("[data-shipment-remove-row]")) {
      const row = event.target.closest("[data-shipment-row]");
      if (row && rows.querySelectorAll("[data-shipment-row]").length > 1) {
        if (row.querySelector("[data-shipment-prelock]")?.dataset.locked === "true") {
          releaseShipmentPrelock(row, { silent: true }).finally(() => row.remove());
        } else {
          row.remove();
        }
      }
    }
  });

  boxCountInput?.addEventListener("input", () => {
    rows?.querySelectorAll("[data-shipment-row]").forEach(updateShipmentRow);
  });

  shipmentForm.addEventListener("submit", (event) => {
    const boxCount = Math.max(parseInt(boxCountInput?.value || "0", 10) || 0, 0);
    if (boxCount <= 0) return;
    const insufficientRow = Array.from(rows?.querySelectorAll("[data-shipment-row]") || []).find((row) => {
      const externalCode = (row.querySelector("[data-shipment-external-sku]")?.value || "").trim();
      const quantity = Math.max(parseInt(row.querySelector("[data-shipment-quantity]")?.value || "0", 10) || 0, 0);
      const available = externalCode ? parseInt(shipmentAvailableData[externalCode] || "0", 10) || 0 : 0;
      return !!externalCode && quantity > available;
    });
    if (insufficientRow) {
      event.preventDefault();
      const externalCode = (insufficientRow.querySelector("[data-shipment-external-sku]")?.value || "").trim();
      const available = parseInt(shipmentAvailableData[externalCode] || "0", 10) || 0;
      window.alert(`库存不足：${externalCode} 当前实时可用库存只有 ${available}`);
      return;
    }
    const invalidRow = Array.from(rows?.querySelectorAll("[data-shipment-row]") || []).find((row) => {
      const quantity = Math.max(parseInt(row.querySelector("[data-shipment-quantity]")?.value || "0", 10) || 0, 0);
      return quantity > 0 && quantity % boxCount !== 0;
    });
    if (invalidRow) {
      event.preventDefault();
      window.alert("存在某个 SKU 的发货数量不能被箱数整除，请先调整后再确认。");
    }
  });
}

document.querySelectorAll("[data-sortable-table]").forEach((table) => {
  const tbody = table.querySelector("tbody");
  if (!tbody) return;

  const parseNumber = (value) => {
    const normalized = String(value || "").replace(/,/g, "").match(/-?\d+(?:\.\d+)?/);
    return normalized ? Number.parseFloat(normalized[0]) : null;
  };

  const getCellValue = (row, index, type) => {
    const cell = row.children[index];
    const rawValue = cell?.dataset.sortValue ?? cell?.textContent ?? "";
    if (type === "number") {
      return parseNumber(rawValue);
    }
    return String(rawValue).trim();
  };

  const sortRows = (header, index) => {
    const type = header.dataset.sortType || "text";
    const nextDirection = table.dataset.sortIndex === String(index) && table.dataset.sortDirection === "asc" ? "desc" : "asc";
    const directionMultiplier = nextDirection === "asc" ? 1 : -1;
    const rows = Array.from(tbody.querySelectorAll("tr"));

    rows.sort((leftRow, rightRow) => {
      const leftValue = getCellValue(leftRow, index, type);
      const rightValue = getCellValue(rightRow, index, type);
      if (type === "number") {
        if (leftValue === null && rightValue === null) return 0;
        if (leftValue === null) return 1;
        if (rightValue === null) return -1;
        return (leftValue - rightValue) * directionMultiplier;
      }
      if (!leftValue && !rightValue) return 0;
      if (!leftValue) return 1;
      if (!rightValue) return -1;
      return leftValue.localeCompare(rightValue, "zh-CN", { numeric: true }) * directionMultiplier;
    });

    rows.forEach((row) => tbody.appendChild(row));
    table.dataset.sortIndex = String(index);
    table.dataset.sortDirection = nextDirection;
    table.querySelectorAll("th[data-sort-type]").forEach((item) => {
      item.classList.remove("sorted-asc", "sorted-desc");
      item.setAttribute("aria-sort", "none");
    });
    header.classList.add(nextDirection === "asc" ? "sorted-asc" : "sorted-desc");
    header.setAttribute("aria-sort", nextDirection === "asc" ? "ascending" : "descending");
  };

  table.querySelectorAll("th[data-sort-type]").forEach((header) => {
    const columnIndex = Array.from(header.parentElement.children).indexOf(header);
    header.tabIndex = 0;
    header.setAttribute("role", "button");
    header.setAttribute("aria-sort", "none");
    header.title = "点击排序";
    header.addEventListener("click", () => sortRows(header, columnIndex));
    header.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      sortRows(header, columnIndex);
    });
  });
});
