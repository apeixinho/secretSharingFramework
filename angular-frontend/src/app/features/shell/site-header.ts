import { Component, computed, inject, OnInit } from '@angular/core';
import { SecretSharingApiService } from '../../core/services/secret-sharing-api.service';

@Component({
  selector: 'ssf-site-header',
  templateUrl: './site-header.html',
  styleUrl: './site-header.scss',
})
export class SiteHeader implements OnInit {
  private readonly api = inject(SecretSharingApiService);

  readonly health = this.api.healthStatus;
  readonly healthLabel = computed(() => {
    const status = this.health();
    if (status === 'online') {
      return 'API online';
    }
    if (status === 'offline') {
      return 'API offline';
    }
    return 'Checking API';
  });

  ngOnInit(): void {
    this.api.checkHealth().subscribe();
  }

  refreshHealth(): void {
    this.api.checkHealth().subscribe();
  }
}
