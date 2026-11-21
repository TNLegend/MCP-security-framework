"""Focused browser regression: metric cards and readable tool/status/review cells.

Serves built frontend locally and intercepts all API requests using the
existing safe browser fixture. No production account or network writes.
"""
from pathlib import Path
import argparse

from playwright.sync_api import sync_playwright, expect
import gui_browser_smoke as fixture

class LayoutAPI(fixture.MockAPI):
    def read(self, path, query):
        if path == "/servers":
            return [{**fixture.SERVER, "name": "GitMCP", "server_info_title": "GitMCP"}]
        if path == "/tools":
            return [{**fixture.TOOL, "name": "fetch_generic_url_content",
                     "title": "fetch_generic_url_content",
                     "analysis_status": "RESTRICTED",
                     "review_status": "REVIEW_REQUIRED"}]
        if path == "/control-plane/config/active":
            return {"id": "revision-80", "revision_number": 80,
                "schema_version": 1, "status": "PUBLISHED",
                "content_hash": fixture.DIGEST, "published_at": fixture.STAMP,
                "content": {"policy_settings": {"rules": {"default": {}}}}}
        if path == "/control-plane/config/revisions":
            return [self.read("/control-plane/config/active",query)]
        return super().read(path,query)

def assert_badges_contained(page, label, width):
    result=page.evaluate("""() => [...document.querySelectorAll(".table-shell td .badge")].map(el=>{
      const r=el.getBoundingClientRect(), c=el.closest("td").getBoundingClientRect();
      return {text:el.textContent.trim(), inCell:r.left>=c.left-1 &&
              r.right<=c.right+1 && r.top>=c.top-1 && r.bottom<=c.bottom+1,
              actualWidth:Math.round(r.width),cellWidth:Math.round(c.width),
              scrollable:!!el.closest(".table-shell")};
    })""")
    bad=[x for x in result if not x["inCell"]]
    assert not bad, (label,width,bad[:5])
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("dist",type=Path)
    parser.add_argument("--chrome",type=Path,required=True)
    args=parser.parse_args()
    fixture.MockAPI=LayoutAPI
    static=fixture.serve(args.dist)
    cases=0
    try:
        with sync_playwright() as pw:
            browser=pw.chromium.launch(executable_path=str(args.chrome),headless=True)
            try:
                for width in (360,390,768,1280,1600):
                    context,page,api,errors=fixture.open_page(browser,static,"ADMIN",width)
                    try:
                        fixture.navigate(page,"Security rules",width)
                        card_list=page.locator(".rules-page > .summary-grid > .summary-card")
                        expect(card_list).to_have_count(4)
                        schema=card_list.filter(has_text="Schema version")
                        expect(schema).to_have_count(1)
                        expect(schema.locator("strong")).to_have_text("1")
                        assert page.locator(".rules-page .summary-grid > details").count()==0
                        shapes=card_list.evaluate_all("""all=>all.map(el=>{
                            const r=el.getBoundingClientRect();
                            const value=el.querySelector("strong");
                            return {height:r.height,valueSize:getComputedStyle(value).fontSize,
                                    name:el.querySelector("span").textContent.trim(),
                                    top:r.top,bottom:r.bottom};
                        })""")
                        assert len({x["valueSize"] for x in shapes})==1,(width,shapes)
                        # At desktop widths the cards must share the same row and height.
                        if width>=1280:
                            assert len({round(x["height"]) for x in shapes})==1,(width,shapes)
                            assert len({round(x["top"]) for x in shapes})==1,(width,shapes)
                        fixture.check_width(page,f"Security rules at {width}px")
                        assert_badges_contained(page,"Security rules",width)
                        cases+=1

                        fixture.navigate(page,"Security review",width)
                        tbl=page.locator(".analysis-tool-table")
                        expect(tbl.get_by_role("button",name="fetch_generic_url_content")).to_be_visible()
                        row=tbl.locator("tbody tr").first
                        badges=row.locator(".badge")
                        expect(badges).to_have_count(2)
                        assert_badges_contained(page,"Security review",width)
                        expect(badges.nth(0)).to_contain_text("Restricted")
                        expect(badges.nth(1)).to_contain_text("Needs review")
                        result=tbl.evaluate("""el=>{
                            const table=el.querySelector('table');
                            const link=el.querySelector('tbody .table-selection');
                            const shell=el.getBoundingClientRect();
                            const tool=link.getBoundingClientRect();
                            return {width:el.clientWidth,scrollWidth:el.scrollWidth,
                             tableWidth:table.getBoundingClientRect().width,
                             toolWidth:tool.width,
                             toolHeight:tool.height,
                             shellFits:el.getBoundingClientRect().width<=
                               document.querySelector("main").getBoundingClientRect().width+1,
                             badgeStyles:[...el.querySelectorAll("tbody .badge")].map(b=>
                                ({whiteSpace:getComputedStyle(b).whiteSpace,
                                  overflow:getComputedStyle(b).overflow}))};
                        }""")
                        assert result["tableWidth"]>=899,(width,result)
                        assert result["toolWidth"]>=150,(width,result)
                        assert result["toolHeight"]<90,(width,result)
                        assert result["shellFits"],(width,result)
                        if width >= 1280:
                            assert result["scrollWidth"] <= result["width"]+1, (
                                "Desktop tool list must fit without horizontal scrolling",
                                width,result)
                        else:
                            assert result["scrollWidth"] >= result["width"],(width,result)
                        assert all(x["whiteSpace"]=="normal" for x in result["badgeStyles"]),(width,result)
                        assert all(x["overflow"]!="hidden" for x in result["badgeStyles"]),(width,result)
                        fixture.check_width(page,f"Tool review at {width}px")
                        cases+=1

                        # All other table badges should honor their cell boundaries.
                        for label in ("MCP tools","Code scans","Cloud security","Audit history",
                                      "Tool activity","Users"):
                            fixture.navigate(page,label,width)
                            assert_badges_contained(page,label,width)
                            fixture.check_width(page,f"{label} at {width}px")
                            cases+=1
                        assert not errors,(width,errors[:5])
                        assert not api.mutations,(width,api.mutations)
                        print(f"PASS {width}px: metrics, long tool names, status/review badges and page tables")
                    finally:
                        context.close()
            finally:
                browser.close()
    finally:
        static.shutdown()
        static.server_close()
    assert cases==40,cases
    print(f"GUI_LAYOUT_REGRESSION_PASS {cases}/40 page-width cases")

if __name__=="__main__":
    main()
