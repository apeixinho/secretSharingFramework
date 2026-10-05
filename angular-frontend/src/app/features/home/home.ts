import { Component } from '@angular/core';
import { Hero } from '../hero/hero';
import { RecoverSecret } from '../recover/recover-secret';
import { SiteHeader } from '../shell/site-header';
import { SplitSecret } from '../split/split-secret';
import { ShareVault } from '../vault/share-vault';

@Component({
  selector: 'ssf-home',
  imports: [SiteHeader, Hero, SplitSecret, ShareVault, RecoverSecret],
  templateUrl: './home.html',
  styleUrl: './home.scss',
})
export class Home {}
