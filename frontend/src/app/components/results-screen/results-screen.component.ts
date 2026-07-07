import { Component, OnInit, OnDestroy, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService, Secret, IosMetadata } from '../../services/scan.service';
import { trigger, transition, style, animate, state, group } from '@angular/animations';
import { Subscription } from 'rxjs';

@Component({
  selector: 'app-results-screen',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './results-screen.component.html',
  styleUrls: ['./results-screen.component.css'],
  animations: [
    trigger('fadeInOut', [
      transition(':enter', [
        style({ opacity: 0 }),
        animate('150ms', style({ opacity: 1 }))
      ]),
      transition(':leave', [
        animate('150ms', style({ opacity: 0 }))
      ])
    ])
  ]
})
export class ResultsScreenComponent implements OnInit, OnDestroy, AfterViewInit {
  selectedPlatform: 'android' | 'ios' = 'android';
  currentFile: File | null = null;
  secrets: Secret[] = [];
  metadata: {
    packageName: string;
    version: string;
    minSdk: string;
    targetSdk: string;
    permissions: string[];
    activities: Array<{
      name: string;
      exported: boolean;
      intentFilters: Array<{
        actions: string[];
        data: Array<{
          scheme: string;
          host: string;
          path: string;
          pathPrefix: string[];
          pathPattern: string;
          port: string;
          mimeType: string;
        }>;
        priority: number;
      }>;
    }>;
    services: Array<{
      name: string;
      exported: boolean;
    }>;
    contentProviders: Array<{
      name: string;
      exported: boolean;
    }>;
    broadcastReceivers: Array<{
      name: string;
      exported: boolean;
    }>;
    usesLibrary: string[];
    customPermissions: string[];
    usesFeatures: string[];
    resourceData: {
      numberOfStringResource: number;
      drawables: {
        png: number;
        jpg: number;
        gif: number;
        xml: number;
      };
      layouts: number;
    };
  } | null = null;
  // iOS-specific metadata, populated for .ipa scans (platform === 'ios').
  iosMetadata: IosMetadata | null = null;
  // Resolved platform of the current result (what the backend reported), used
  // to decide whether to render Android or iOS sections.
  platform: 'android' | 'ios' = 'android';
  particlePositions: Array<{top: string, left: string, size: string, delay: string}> = [];

  // Section visibility states - all collapsed by default
  showPermissions = false;
  showActivities = false;
  showServices = false;
  showContentProviders = false;
  showBroadcastReceivers = false;
  showLibraries = false;
  showCustomPermissions = false;
  showFeatures = false;
  showResourceData = false;
  showDeeplinks = false;
  // iOS section visibility states.
  showUrlSchemes = false;
  showFrameworks = false;
  showEntitlements = false;

  private platformSubscription?: Subscription;
  private resultPlatformSubscription?: Subscription;
  private fileSubscription?: Subscription;
  private secretsSubscription?: Subscription;
  private metadataSubscription?: Subscription;
  private iosMetadataSubscription?: Subscription;
  private particleSubscription?: Subscription;
  // Performance optimizations
  private readonly SCROLL_THRESHOLD = 100;
  private readonly DEBOUNCE_TIME = 100;
  private lastScrollTime = 0;
  // Held so they can be torn down in ngOnDestroy — otherwise the observer and
  // the window scroll listener outlive the component and leak.
  private scrollObserver?: IntersectionObserver;
  private parallaxScrollHandler?: () => void;

  constructor(private scanService: ScanService) {}

  ngOnInit() {
    this.setupSubscriptions();
  }

  ngOnDestroy() {
    this.cleanupSubscriptions();
    this.scrollObserver?.disconnect();
    if (this.parallaxScrollHandler) {
      window.removeEventListener('scroll', this.parallaxScrollHandler);
    }
  }

  private setupSubscriptions() {
    this.particleSubscription = this.scanService.particlePositions$.subscribe(positions => {
      this.particlePositions = positions;
    });
    
    this.platformSubscription = this.scanService.selectedPlatform$.subscribe(platform => {
      this.selectedPlatform = platform;
    });

    // resultPlatform$ reflects the platform the backend actually reported for
    // the completed scan; drive section rendering off this rather than the
    // user's tab selection.
    this.resultPlatformSubscription = this.scanService.resultPlatform$.subscribe(platform => {
      this.platform = platform;
    });

    this.fileSubscription = this.scanService.currentFile$.subscribe(file => {
      this.currentFile = file;
    });

    this.secretsSubscription = this.scanService.secrets$.subscribe(secrets => {
      this.secrets = secrets;
    });

    this.metadataSubscription = this.scanService.metadata$.subscribe(metadata => {
      this.metadata = metadata;
    });

    this.iosMetadataSubscription = this.scanService.iosMetadata$.subscribe(iosMetadata => {
      this.iosMetadata = iosMetadata;
    });
  }

  private cleanupSubscriptions() {
    [
      this.particleSubscription,
      this.platformSubscription,
      this.resultPlatformSubscription,
      this.fileSubscription,
      this.secretsSubscription,
      this.metadataSubscription,
      this.iosMetadataSubscription
    ].forEach(sub => sub?.unsubscribe());
  }

  // Scroll animation logic
  private setupScrollAnimations(): void {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('revealed');
          // Optional: Stop observing after reveal
          // observer.unobserve(entry.target);
        }
      });
    }, {
      threshold: 0.1, // Trigger when 10% of the element is visible
      rootMargin: '0px' // Start animation as soon as element enters viewport
    });
    this.scrollObserver = observer;

    // Observe all elements with animation classes
    document.querySelectorAll('.scroll-reveal, .scroll-reveal-left, .scroll-reveal-right, .scroll-scale, .text-reveal')
      .forEach(el => observer.observe(el));

    // Parallax effect for background
    const parallaxBg = document.querySelector('.parallax-bg') as HTMLElement;
    if (parallaxBg) {
      const handler = () => {
        const scrolled = window.pageYOffset;
        parallaxBg.style.transform = `translateY(${scrolled * 0.1}px)`;
      };
      this.parallaxScrollHandler = handler;
      window.addEventListener('scroll', handler);
    }
  }

  ngAfterViewInit() {
    this.setupScrollAnimations();
  }

  // Optimized section toggling
  private toggleSection(section: 'showPermissions' | 'showActivities' | 'showServices' |
    'showContentProviders' | 'showBroadcastReceivers' | 'showLibraries' |
    'showCustomPermissions' | 'showFeatures' | 'showResourceData' | 'showDeeplinks' |
    'showUrlSchemes' | 'showFrameworks' | 'showEntitlements') {
    requestAnimationFrame(() => {
      this[section] = !this[section];
    });
  }

  // Event handlers with debouncing
  onItemHover(event: MouseEvent) {
    const now = Date.now();
    if (now - this.lastScrollTime < this.DEBOUNCE_TIME) return;
    this.lastScrollTime = now;

    const element = event.currentTarget as HTMLElement;
    const container = element.closest('.section-content');
    if (!container) return;

    const rect = element.getBoundingClientRect();
    if (rect.top < this.SCROLL_THRESHOLD) {
      requestAnimationFrame(() => {
        (container as HTMLElement).scrollTo({
          top: (container as HTMLElement).scrollTop - (this.SCROLL_THRESHOLD - rect.top),
          behavior: 'auto'
        });
      });
    }
  }

  // Toggle methods
  togglePermissions() { this.toggleSection('showPermissions'); }
  toggleActivities() { this.toggleSection('showActivities'); }
  toggleServices() { this.toggleSection('showServices'); }
  toggleContentProviders() { this.toggleSection('showContentProviders'); }
  toggleBroadcastReceivers() { this.toggleSection('showBroadcastReceivers'); }
  toggleLibraries() { this.toggleSection('showLibraries'); }
  toggleCustomPermissions() { this.toggleSection('showCustomPermissions'); }
  toggleFeatures() { this.toggleSection('showFeatures'); }
  toggleResourceData() { this.toggleSection('showResourceData'); }
  toggleDeeplinks() { this.toggleSection('showDeeplinks'); }
  // iOS toggle methods
  toggleUrlSchemes() { this.toggleSection('showUrlSchemes'); }
  toggleFrameworks() { this.toggleSection('showFrameworks'); }
  toggleEntitlements() { this.toggleSection('showEntitlements'); }

  // iOS entitlements are a free-form object; flatten to display rows of
  // key -> stringified value. Nested arrays/objects are JSON-encoded so they
  // remain readable in the UI without special-casing every shape.
  getEntitlementEntries(): Array<{ key: string; value: string }> {
    const ent = this.iosMetadata?.entitlements;
    if (!ent) return [];
    return Object.keys(ent).map(key => {
      const raw = (ent as Record<string, unknown>)[key];
      let value: string;
      if (raw === null || raw === undefined) {
        value = '';
      } else if (typeof raw === 'object') {
        try {
          value = JSON.stringify(raw);
        } catch {
          value = String(raw);
        }
      } else {
        value = String(raw);
      }
      return { key, value };
    });
  }

  getEntitlementCount = () => this.getEntitlementEntries().length;

  trackByEntitlement = (_: number, e: { key: string }) => e.key;

  // Helper methods
  getActivitiesWithDeeplinks() {
    if (!this.metadata?.activities) return [];

    return this.metadata.activities.filter(activity => {
      return activity.intentFilters?.some(filter => 
        filter.actions?.includes('android.intent.action.VIEW') && 
        filter.data?.some(data => data?.scheme)
      ) ?? false;
    });
  }

  getDeeplinksCount = () => this.getActivitiesWithDeeplinks().length;

  formatDeeplink(data: { scheme: string; host?: string; path?: string; pathPrefix?: string[]; pathPattern?: string; port?: string; }) {
    const path = data.path ?? data.pathPattern ?? data.pathPrefix?.[0] ?? '';
    const scheme = data.scheme?.trim();
    // An empty or malformed scheme makes `new URL(scheme + '://')` throw a
    // TypeError, which would otherwise propagate out of the template binding and
    // blank the deeplink section. Guard with a plain-string fallback.
    if (!scheme) {
      return `${data.host ?? ''}${path}`;
    }
    try {
      const url = new URL(`${scheme}://`);
      if (data.host) {
        url.host = data.host;
        if (data.port) url.port = data.port;
      }
      url.pathname = path;
      return url.toString();
    } catch {
      return `${scheme}://${data.host ?? ''}${path}`;
    }
  }

  isExported = (component: { exported: boolean }) => component.exported;

  getTotalDrawables(): number {
    const drawables = this.metadata?.resourceData?.drawables;
    if (!drawables) return 0;
    return drawables.png + drawables.jpg + drawables.gif + drawables.xml;
  }

  getFileSize = () => this.currentFile ? 
    `${(this.currentFile.size / 1024 / 1024).toFixed(2)} MB` : 'Unknown';

  async copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      // Could add a toast notification here
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  }

  getSecretCountBySeverity = (confidence: 'high' | 'low') => 
    this.scanService.getSecretCountBySeverity(confidence);

  cleanFilePath(path: string): string {
    // Show only the in-APK relative path. Match on the structural
    // `output/apk/source/` segment rather than the full hardcoded temp root, so
    // a reconfigured backend output dir (env/volume root) no longer leaks raw
    // server filesystem paths into the UI. NOTE: the robust fix is for the
    // backend to return paths relative to the scan root (or expose the
    // strip-prefix via a shared config/response field); this is the client-side
    // mitigation achievable within the frontend.
    const marker = 'output/apk/source/';
    const idx = path.indexOf(marker);
    return idx >= 0 ? path.slice(idx + marker.length) : path;
  }

  // trackBy fns prevent the entire list from being re-rendered when the
  // underlying data is replaced/reordered. Used by *ngFor in the template.
  trackByIndex = (i: number) => i;
  trackByValue = (_: number, v: string) => v;
  trackByName = (_: number, item: { name?: string }) => item?.name ?? '';
  trackBySecret = (_: number, s: Secret) =>
    `${s.fileLocation}:${s.lineNo}:${s.secretType}:${s.secretString}`;

  resetScan = () => this.scanService.resetScan();
}
