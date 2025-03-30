import { Component, OnInit, OnDestroy, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ScanService, Secret } from '../../services/scan.service';
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

  private platformSubscription?: Subscription;
  private fileSubscription?: Subscription;
  private secretsSubscription?: Subscription;
  private metadataSubscription?: Subscription;
  private particleSubscription?: Subscription;
  // Performance optimizations
  private readonly SCROLL_THRESHOLD = 100;
  private readonly DEBOUNCE_TIME = 100;
  private lastScrollTime = 0;

  constructor(private scanService: ScanService) {}

  ngOnInit() {
    this.setupSubscriptions();
  }

  ngOnDestroy() {
    this.cleanupSubscriptions();
  }

  private setupSubscriptions() {
    this.particleSubscription = this.scanService.particlePositions$.subscribe(positions => {
      this.particlePositions = positions;
    });
    
    this.platformSubscription = this.scanService.selectedPlatform$.subscribe(platform => {
      this.selectedPlatform = platform;
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
  }

  private cleanupSubscriptions() {
    [
      this.particleSubscription,
      this.platformSubscription,
      this.fileSubscription,
      this.secretsSubscription,
      this.metadataSubscription
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

    // Observe all elements with animation classes
    document.querySelectorAll('.scroll-reveal, .scroll-reveal-left, .scroll-reveal-right, .scroll-scale, .text-reveal')
      .forEach(el => observer.observe(el));

    // Parallax effect for background
    const parallaxBg = document.querySelector('.parallax-bg') as HTMLElement;
    if (parallaxBg) {
      window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        parallaxBg.style.transform = `translateY(${scrolled * 0.1}px)`;
      });
    }
  }

  ngAfterViewInit() {
    this.setupScrollAnimations();
  }

  // Optimized section toggling
  private toggleSection(section: 'showPermissions' | 'showActivities' | 'showServices' | 
    'showContentProviders' | 'showBroadcastReceivers' | 'showLibraries' | 
    'showCustomPermissions' | 'showFeatures' | 'showResourceData' | 'showDeeplinks') {
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
    const url = new URL(`${data.scheme}://`);
    if (data.host) {
      url.host = data.host;
      if (data.port) url.port = data.port;
    }
    url.pathname = data.path ?? data.pathPattern ?? data.pathPrefix?.[0] ?? '';
    return url.toString();
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
    return path.replace('/tmp/morf/output/apk/source/', '');
  }


  resetScan = () => this.scanService.resetScan();
}
