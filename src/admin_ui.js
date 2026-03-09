import { renderAdminPage, renderAdminPageScript } from "./ui.js";

function createAdminUiApi() {
  function handleAdminPage() {
    return renderAdminPage();
  }

  function handleAdminPageScriptAsset() {
    return new Response(renderAdminPageScript(), {
      headers: {
        "content-type": "application/javascript; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  return {
    handleAdminPage,
    handleAdminPageScriptAsset,
  };
}

export { createAdminUiApi };
