"""Activity heatmap visual — renders a GitHub-style contribution graph in the stats panel.

Requires the TUI stats panel to be visible (/stats toggle).
Updates the heatmap data from NetworkAnalytics on a 30-second timer.
"""

import time

__plugin_name__ = "Activity Heatmap"
__plugin_version__ = "1.0"
__plugin_author__ = "eyearesee"
__plugin_desc__ = "GitHub-style contribution heatmap in the stats panel"


def setup(api):
    tui = api._tui
    if tui is None:
        return

    @api.on("on_message")
    def _on_message(nick, target, text, **kwargs):
        pass  # NetworkAnalytics.record_message already tracks this

    # Register the /heatmap command (overrides the built-in if not already)
    # The built-in command renders a text heatmap to the status window.
    # This plugin enhances it with a visual stats panel if visible.

    @api.command("hm")
    def cmd_hm(api, args):
        """Quick /hm alias for /heatmap with visual output."""
        tui._slash_heatmap(args, "", "/heatmap " + args)
        # If stats panel is visible, queue a refresh
        if getattr(tui, '_show_stats_panel', False):
            tui.dirty = True
