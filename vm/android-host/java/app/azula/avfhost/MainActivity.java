package app.azula.avfhost;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {
    static volatile MainActivity current;
    private final Handler h = new Handler(Looper.getMainLooper());
    private TextView statusView;
    private final Runnable tick = new Runnable() {
        @Override public void run() {
            statusView.setText("Status: " + HostService.status + "\nHidden API: " + App.bypassResult);
            h.postDelayed(this, 1000);
        }
    };

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        current = this;
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        int p = (int) (24 * getResources().getDisplayMetrics().density);
        root.setPadding(p, p * 2, p, p);
        statusView = new TextView(this);
        Button start = new Button(this);
        start.setText("Start VM");
        start.setOnClickListener(v -> startForegroundService(
                new Intent(this, HostService.class).setAction(HostService.ACTION_START)));
        Button stop = new Button(this);
        stop.setText("Stop VM");
        stop.setOnClickListener(v -> startForegroundService(
                new Intent(this, HostService.class).setAction(HostService.ACTION_STOP)));
        root.addView(statusView);
        root.addView(start);
        root.addView(stop);
        setContentView(root);
        if (getIntent().getBooleanExtra("finish", false)) finishAndRemoveTask();
    }

    /** `am start ... --ez finish true` closes and removes the task (like swiping it from recents). */
    @Override protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        if (i.getBooleanExtra("finish", false)) finishAndRemoveTask();
    }

    @Override protected void onDestroy() { if (current == this) current = null; super.onDestroy(); }

    @Override protected void onResume() { super.onResume(); h.post(tick); }
    @Override protected void onPause() { h.removeCallbacks(tick); super.onPause(); }
}
